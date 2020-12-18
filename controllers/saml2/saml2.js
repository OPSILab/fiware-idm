const models = require('../../models/models.js');
const config_service = require('../../lib/configService.js');
const config = config_service.get_config();
const fs = require('fs');
const debug = require('debug')('idm:saml2_controller');
const exec = require('child_process').exec;
const saml2 = require('../../lib/saml2.js');
const image = require('../../lib/image.js');
const gravatar = require('gravatar');

const config_attributes = require('../../etc/eidas/requested_attributes.json');
const config_attributes_natural = Object.keys(config_attributes.NaturalPerson);
const config_attributes_legal = Object.keys(config_attributes.LegalPerson);
const config_attributes_representative = Object.keys(config_attributes.RepresentativeNaturalPerson);

// Select SAML authentication (Eidas or Spid)
const saml_authentication = config.eidas.enabled ? 'eidas' : (config.spid.enabled ? 'spid' : 'none');

const spid_controller = require('./spid');
// Create identity provider (if eidas is enables, takes precedence, otherwise SPID is configured)
let idp_options;


if (saml_authentication === 'spid')
    idp_options = {
        sso_login_url: config.spid.node_host, // config.eidas.idp_host should be deprectated
        sso_logout_url: 'https://' + config.spid.gateway_host + '/saml2/logout',
        certificates: [],
        nameid_format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
    };
else
    idp_options = {
        sso_login_url: config.eidas.node_host || config.eidas.idp_host, // config.eidas.idp_host should be deprectated
        sso_logout_url: 'https://' + config.eidas.gateway_host + '/saml2/logout',
        certificates: []
    };

const idp = new saml2.IdentityProvider(idp_options);

const sp_states = {};
const sp_redirect_uris = {};


// GET /idm/applications/:application_id/step/eidas -- Form to add eIDAs/SPID credentials to application
exports.step_new_eidas_credentials = function (req, res) {
    debug('--> step_new_eidas_credentials');
    res.render('saml2/step_create_eidas_credentials', {
        application: req.application,
        eidas_credentials: [],
        errors: [],
        csrf_token: req.csrfToken()
    });
};


// POST /idm/applications/:application_id/step/eidas -- Create eIDAs credentials
exports.step_create_eidas_credentials = function (req, res) {
    debug('--> step_create_eidas_credentials');

    const eidas_credentials = models.eidas_credentials.build(req.body.eidas_credentials);

    eidas_credentials.oauth_client_id = req.application.id;

    eidas_credentials.attributes_list = {
        // eslint-disable-next-line snakecase/snakecase
        NaturalPerson: ['PersonIdentifier', 'FamilyName', 'FirstName', 'DateOfBirth'],
        LegalPerson: [], // eslint-disable-line snakecase/snakecase
        RepresentativeNaturalPerson: [] // eslint-disable-line snakecase/snakecase
    };

    return eidas_credentials
        .validate()
        .then(function () {
            return eidas_credentials.save();
        })
        .then(function () {
            return exports.generate_app_certificates(req.application.id, eidas_credentials);
        })
        .then(function () {
            return res.redirect('/idm/applications/' + req.application.id + '/step/avatar');
        })
        .catch(function (error) {
            debug('Error: ', error);

            const name_errors = [];

            if (error.errors && error.errors.length) {
                for (const i in error.errors) {
                    name_errors.push(error.errors[i].message);
                }
            }

            res.locals.message = {
                text: ' Fail creating eidas credentials.',
                type: 'warning'
            };

            return res.render('saml2/step_create_eidas_crendentials', {
                application: req.application,
                eidas_credentials,
                errors: name_errors,
                csrf_token: req.csrfToken()
            });
        });
};

// GET /idm/applications/:application_id/edit/eidas -- Render edit eIDAs credentials view
exports.edit_eidas_crendentials = function (req, res) {
    debug('--> edit_eidas_crendentials');

    res.render('saml2/edit_eidas', {
        application: req.application,
        eidas_credentials: req.eidas_credentials,
        errors: [],
        csrf_token: req.csrfToken()
    });
};

// PUT /idm/applications/:application_id/edit/eidas/info -- Update eIDAS Info
exports.update_eidas_info = function (req, res) {
    debug('--> update_eidas_info');

    const eidas_credentials = models.eidas_credentials.build(req.body.eidas_credentials);
    eidas_credentials.oauth_client_id = req.application.id;

    eidas_credentials
        .validate()
        .then(function () {
            return models.eidas_credentials.update(
                {
                    support_contact_person_name: req.body.eidas_credentials.support_contact_person_name,
                    support_contact_person_surname: req.body.eidas_credentials.support_contact_person_surname,
                    support_contact_person_email: req.body.eidas_credentials.support_contact_person_email,
                    support_contact_person_telephone_number: req.body.eidas_credentials.support_contact_person_telephone_number,
                    support_contact_person_company: req.body.eidas_credentials.support_contact_person_company,
                    technical_contact_person_name: req.body.eidas_credentials.technical_contact_person_name,
                    technical_contact_person_surname: req.body.eidas_credentials.technical_contact_person_surname,
                    technical_contact_person_email: req.body.eidas_credentials.technical_contact_person_email,
                    technical_contact_person_telephone_number:
                        req.body.eidas_credentials.technical_contact_person_telephone_number,
                    technical_contact_person_company: req.body.eidas_credentials.technical_contact_person_company,
                    organization_name: req.body.eidas_credentials.organization_name,
                    organization_url: req.body.eidas_credentials.organization_url,
                    organization_nif: req.body.eidas_credentials.organization_nif,
                    sp_type: req.body.eidas_credentials.sp_type
                },
                {
                    fields: [
                        'support_contact_person_name',
                        'support_contact_person_surname',
                        'support_contact_person_email',
                        'support_contact_person_telephone_number',
                        'support_contact_person_company',
                        'technical_contact_person_name',
                        'technical_contact_person_surname',
                        'technical_contact_person_email',
                        'technical_contact_person_telephone_number',
                        'technical_contact_person_company',
                        'organization_name',
                        'organization_url',
                        'organization_nif',
                        'sp_type'
                    ],
                    where: { oauth_client_id: req.application.id }
                }
            );
        })
        .then(function () {
            // Send message of success of updating the application
            req.session.message = {
                text: ' eIDAS info updated successfully.',
                type: 'success'
            };
            res.redirect('/idm/applications/' + req.application.id);
        })
        .catch(function (error) {
            debug('Error: ', error);

            // Send message of warning of updating the application
            res.locals.message = {
                text: ' Unable to update eIDAS info.',
                type: 'warning'
            };
            req.body.eidas_credentials.attributes_list = req.eidas_credentials.attributes_list;

            const name_errors = [];
            if (error.errors && error.errors.length) {
                for (const i in error.errors) {
                    name_errors.push(error.errors[i].message);
                }
            }
            res.render('saml2/edit_eidas', {
                application: req.application,
                eidas_credentials: req.body.eidas_credentials,
                errors: name_errors,
                csrf_token: req.csrfToken()
            });
        });
};

// PUT /idm/applications/:application_id/edit/eidas/attributes -- Update eIDAS attributes
exports.update_eidas_attributes = function (req, res) {
    debug('--> update_eidas_attributes');

    const attributes_list = {
        // eslint-disable-next-line snakecase/snakecase
        NaturalPerson: ['PersonIdentifier', 'FamilyName', 'FirstName', 'DateOfBirth'],
        LegalPerson: [], // eslint-disable-line snakecase/snakecase
        RepresentativeNaturalPerson: [] // eslint-disable-line snakecase/snakecase
    };

    if (req.body.NaturalPerson) {
        const array_natural = Object.keys(req.body.NaturalPerson);
        for (let i = 0; i < array_natural.length; i++) {
            if (
                config_attributes_natural.includes(array_natural[i]) &&
                !attributes_list.NaturalPerson.includes(array_natural[i])
            ) {
                attributes_list.NaturalPerson.push(array_natural[i]);
            }
        }
    }

    if (req.body.LegalPerson) {
        const array_legal = Object.keys(req.body.LegalPerson);
        for (let i = 0; i < array_legal.length; i++) {
            if (config_attributes_legal.includes(array_legal[i]) && !attributes_list.LegalPerson.includes(array_legal[i])) {
                attributes_list.LegalPerson.push(array_legal[i]);
            }
        }
    }

    if (req.body.RepresentativeNaturalPerson) {
        const array_representative = Object.keys(req.body.RepresentativeNaturalPerson);
        for (let i = 0; i < array_representative.length; i++) {
            if (
                config_attributes_representative.includes(array_representative[i]) &&
                !attributes_list.RepresentativeNaturalPerson.includes(array_representative[i])
            ) {
                attributes_list.RepresentativeNaturalPerson.push(array_representative[i]);
            }
        }
    }

    models.eidas_credentials
        .update(
            {
                attributes_list
            },
            {
                fields: ['attributes_list'],
                where: { oauth_client_id: req.application.id }
            }
        )
        .then(function () {
            req.session.message = {
                text: ' eIDAS attributes successfully updated.',
                type: 'success'
            };
            res.redirect('/idm/applications/' + req.application.id);
        })
        .catch(function (error) {
            debug('Error', error);
            req.session.message = {
                text: ' Fail update eIDAS attributes.',
                type: 'danger'
            };
            res.redirect('/idm/applications/' + req.application.id);
        });
};

// GET /idm/applications/:application_id/saml2/metadata -- Expose metadata
exports.saml2_metadata = function (req, res) {
    debug('--> saml2_metadata');

    res.type('application/xml');
    res.send(req.sp.create_metadata());
};

// POST /saml2/login -- Redirect to eIDAs or SPID Identity Provider
exports.login = function (req, res) {
    debug('--> login');

    delete req.body.email;
    delete req.body.password;
    delete req.query;
    if (saml_authentication === 'spid')
        res.redirect(307, idp.sso_login_url + '/sso');
    else
        res.redirect(307, idp.sso_login_url);
};

// POST /idm/applications/:application_id/saml2/login -- Response from eIDAs or SPID with user credentials
exports.saml2_application_login = function (req, res) {
    debug('--> saml2_application_login', req.url);

    const options = {
        request_body: req.body, saml_type: saml_authentication
    };

    return req.sp.post_assert(idp, options, function (error, saml_response) {
        if (error != null) {
            res.locals.error = error;
            return res.render('errors/saml', { application: req.application });
        }

        // Save name_id and session_index for logout
        // Note:  In practice these should be saved in the user session, not globally.
        let name_id;
        if (saml_authentication === 'eidas')
            name_id = saml_response.user.attributes.PersonIdentifier[0];
        else
            name_id = saml_response.user.attributes.name[0];

        // Commented beacuase no session index was returned when testing was performed
        //var session_index = saml_response.user.session_index;

        // Response To variable to check state of previous request
        const response_to = saml_response.response_to;

        const saml_profile = {};

        for (const key in saml_response.user.attributes) {
            // if (saml_response.user.attributes.hasOwnProperty(key)) {
            if (Object.prototype.hasOwnProperty.call(saml_response.user.attributes, key)) {
                if (saml_authentication === 'eidas')
                    saml_profile[key] = saml_response.user.attributes[key][0];
                else
                    saml_profile[key] = saml_response.user.attributes[key][0];
            }
        }

        return create_user(name_id, saml_profile)
            .then(function (user) {
                let image = '/img/logos/small/user.png';
                if (user.email && user.gravatar) {
                    image = gravatar.url(user.email, { s: 25, r: 'g', d: 'mm' }, { protocol: 'https' });
                } else if (user.image !== 'default') {
                    image = '/img/users/' + user.image;
                }

                req.session.user = {
                    id: user.id,
                    username: user.username,
                    image,
                    oauth_sign_in: true
                };

                let state;
                let redirect_uri;
                if (saml_authentication === 'spid') {

                    state = spid_controller.sp_states[response_to] ? spid_controller.sp_states[response_to] : 'xyz';
                    redirect_uri = spid_controller.sp_redirect_uris[response_to]
                        ? spid_controller.sp_redirect_uris[response_to] : req.application.redirect_uri[0].split(',')[0];
                } else {
                    state = sp_states[response_to] ? sp_states[response_to] : 'xyz';
                    redirect_uri = sp_redirect_uris[response_to]
                        ? sp_redirect_uris[response_to] : req.application.redirect_uri.split(',')[0];
                }


                const path =
                    '/oauth2/authorize?' +
                    'response_type=code&' +
                    'client_id=' +
                    req.application.id +
                    '&' +
                    'state=' +
                    state +
                    '&' +
                    'redirect_uri=' +
                    redirect_uri;

                res.redirect(path);
            })
            .catch(function (error) {
                debug('Error', error);
                req.session.errors = error;
                res.redirect('/auth/login');
            });
    });
};

// Create a user when Saml flow has already finished
function create_user(name_id, new_saml_profile) {
    let image_name = 'default';
    return image.toImage(new_saml_profile.CurrentPhoto, 'public/img/users').then(function (file_name) {
        if (file_name) {
            image_name = file_name;
            delete new_saml_profile.CurrentPhoto;
        }

        return models.user
            .findOne({
                where: {
                    [saml_authentication + '_id']: saml_authentication === 'eidas' ?
                        name_id :
                        name_id + '_' + new_saml_profile.familyName
                }
            })
            .then(function (user) {
                if (user) {

                    // Update de eidas profile
                    const actual_saml_profile_keys = Object.keys(user.extra.saml_profile);
                    const new_saml_profile_keys = Object.keys(new_saml_profile);

                    const difference = new_saml_profile_keys.filter((x) => !actual_saml_profile_keys.includes(x));
                    const new_attributes = user.extra.saml_profile;

                    for (let i = 0; i < difference.length; i++) {
                        new_attributes[difference[i]] = new_saml_profile[difference[i]];
                    }
                    const user_extra = user.extra;
                    Object.assign(user_extra.saml_profile, new_attributes);
                    user.extra = user_extra;
                    user.email = new_saml_profile.Email && !user.email ? new_saml_profile.Email : user.email;

                    // If user has eIDAs photo destroy previous one (if it exists) and create a new one
                    const image_old = image_name !== 'default' ? user.image : 'default';
                    user.image = image_name !== 'default' ? image_name : user.image;

                    return image.destroy('public/img/users/' + image_old).then(function () {
                        return user.save({
                            fields: ['extra', 'email', 'image']
                        });
                    });
                }

                if (saml_authentication === 'eidas')
                    return models.user
                        .build({
                            username: new_saml_profile.FirstName + '_' + new_saml_profile.FamilyName,
                            eidas_id: name_id,
                            email: new_saml_profile.Email ? new_saml_profile.Email : null,
                            image: image_name !== 'default' ? image_name : 'default',
                            extra: { saml_profile: new_saml_profile },
                            enabled: true
                        })
                        .save();
                else // SPID Authentication
                    return models.user
                        .build({
                            username: new_saml_profile.name + '_' + new_saml_profile.familyName,
                            spid_id: name_id + '_' + new_saml_profile.familyName,
                            email: new_saml_profile.email ? new_saml_profile.email : null,
                            image: image_name !== 'default' ? image_name : 'default',
                            extra: { saml_profile: new_saml_profile },
                            enabled: true
                        })
                        .save();
            })
            .then(function (user) {
                return user;
            })
            .catch(function (error) {
                debug('Error', error);
                return Promise.reject(error);
            });
    });
}

// Search Saml (eidas or spid) credentials associated to application
exports.search_saml_credentials = function (req, res, next) {
    debug('--> search_saml_credentials');

    if (saml_authentication === 'eidas') {
        exports.search_eidas_credentials(req, res, next);
    } else if (saml_authentication === 'spid') {
        exports.search_spid_credentials(req, res, next);
    } else {
        throw new Error("No Saml authentication enabled");
    }
}

// Search spid credentials associated to application
exports.search_spid_credentials = function (req, res, next) {
    debug('--> search_spid_credentials');

    models.spid_credentials
        .findOne({
            where: { oauth_client_id: req.application.id }
        })
        .then(function (credentials) {
            if (credentials) {
                const organization = {
                    name: credentials.organization_name,
                    url: credentials.organization_url
                };

                const contact = {
                    support: {
                        company: credentials.support_contact_person_company,
                        name: credentials.support_contact_person_name,
                        surname: credentials.support_contact_person_surname,
                        email: credentials.support_contact_person_email,
                        telephone_number: credentials.support_contact_person_telephone_number
                    },
                    technical: {
                        company: credentials.technical_contact_person_company,
                        name: credentials.technical_contact_person_name,
                        surname: credentials.technical_contact_person_surname,
                        email: credentials.technical_contact_person_email,
                        telephone_number: credentials.technical_contact_person_telephone_number
                    }
                };

                // Create service provider
                const sp_options = {
                    entity_id:
                        'https://' + config.spid.gateway_host + '/idm/applications/' + req.application.id + '/saml2/metadata',
                    private_key: fs.readFileSync('certs/applications/' + req.application.id + '-key.pem').toString(),
                    certificate: fs.readFileSync('certs/applications/' + req.application.id + '-cert.pem').toString(),
                    assert_endpoint:
                        'https://' + config.spid.gateway_host + '/idm/applications/' + req.application.id + '/saml2/login',
                    audience: 'https://' + config.spid.gateway_host + '/idm/applications/' + req.application.id + '/saml2/login',
                    sign_get_request: true,
                    nameid_format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                    provider_name: credentials.organization_nif,
                    auth_context: {
                        comparison: 'minimum',
                        // eslint-disable-next-line snakecase/snakecase
                        AuthnContextClassRef: [
                            // 'https://www.spid.gov.it/SpidL1',
                            'https://www.spid.gov.it/SpidL2']
                        //'https://www.spid.gov.it/SpidL3']
                    },
                    attributes_list: credentials.attributes_list,
                    saml_type: saml_authentication,
                    force_authn: true,
                    organization,
                    contact,
                    valid_until: config.spid.metadata_expiration,
                    sp_type: credentials.sp_type
                };

                const sp = new saml2.ServiceProvider(sp_options);

                req.spid_credentials = credentials;

                req.sp = sp;
                next();
            } else {
                next();
            }
        })
        .catch(function (error) {
            debug('Error', error);
            req.session.errors = error;
            res.redirect('/');
        });


};

// Search eidas credentials associated to application
exports.search_eidas_credentials = function (req, res, next) {
    debug('--> search_eidas_credentials');

    models.eidas_credentials
        .findOne({
            where: { oauth_client_id: req.application.id }
        })
        .then(function (credentials) {
            if (credentials) {
                const organization = {
                    name: credentials.organization_name,
                    url: credentials.organization_url
                };

                const contact = {
                    support: {
                        company: credentials.support_contact_person_company,
                        name: credentials.support_contact_person_name,
                        surname: credentials.support_contact_person_surname,
                        email: credentials.support_contact_person_email,
                        telephone_number: credentials.support_contact_person_telephone_number
                    },
                    technical: {
                        company: credentials.technical_contact_person_company,
                        name: credentials.technical_contact_person_name,
                        surname: credentials.technical_contact_person_surname,
                        email: credentials.technical_contact_person_email,
                        telephone_number: credentials.technical_contact_person_telephone_number
                    }
                };

                // Create service provider
                const sp_options = {
                    entity_id:
                        'https://' + config.eidas.gateway_host + '/idm/applications/' + req.application.id + '/saml2/metadata',
                    private_key: fs.readFileSync('certs/applications/' + req.application.id + '-key.pem').toString(),
                    certificate: fs.readFileSync('certs/applications/' + req.application.id + '-cert.pem').toString(),
                    assert_endpoint:
                        'https://' + config.eidas.gateway_host + '/idm/applications/' + req.application.id + '/saml2/login',
                    audience: 'https://' + config.eidas.gateway_host + '/idm/applications/' + req.application.id + '/saml2/login',
                    sign_get_request: true,
                    nameid_format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
                    provider_name: credentials.organization_nif,
                    auth_context: {
                        comparison: 'minimum',
                        // eslint-disable-next-line snakecase/snakecase
                        AuthnContextClassRef: ['http://eidas.europa.eu/LoA/low']
                    },
                    force_authn: true,
                    organization,
                    contact,
                    valid_until: config.eidas.metadata_expiration,
                    sp_type: credentials.sp_type
                };

                const sp = new saml2.ServiceProvider(sp_options);

                req.eidas_credentials = credentials;

                req.sp = sp;
                next();
            } else {
                next();
            }
        })
        .catch(function (error) {
            debug('Error', error);
            req.session.errors = error;
            res.redirect('/');
        });
};

const get_redirect_uri = function (url) {
    const params = url.split('?')[1].split('&');
    let redirect_uri = '';
    for (const p in params) {
        if (params[p].split('=')[0] === 'redirect_uri') {
            redirect_uri = params[p].split('=')[1];
        }
    }

    return redirect_uri;
};

const get_state = function (url) {
    const params = url.split('?')[1].split('&');
    let state = '';
    for (const p in params) {
        if (params[p].split('=')[0] === 'state') {
            state = params[p].split('=')[1];
        }
    }

    return state;
};


exports.create_auth_request = function (req, res, next) {

    if (saml_authentication === 'eidas')
        create_eidas_auth_request(req, res, next);
    else
        spid_controller.create_spid_auth_request(idp, req, res, next);
}



// Create auth xml request for Eidas to be send to the idp
function create_eidas_auth_request(req, res, next) {
    if (req.sp) {
        const array_natural = req.eidas_credentials.attributes_list.NaturalPerson;
        const array_legal = req.eidas_credentials.attributes_list.LegalPerson;
        const array_representative = req.eidas_credentials.attributes_list.RepresentativeNaturalPerson;
        const extensions = {
            'eidas:SPType': req.eidas_credentials.sp_type,
            'eidas:RequestedAttributes': []
        };

        for (let i = 0; i < array_natural.length; i++) {
            extensions['eidas:RequestedAttributes'].push({
                'eidas:RequestedAttribute': config_attributes.NaturalPerson[array_natural[i]]
            });
        }

        for (let i = 0; i < array_legal.length; i++) {
            extensions['eidas:RequestedAttributes'].push({
                'eidas:RequestedAttribute': config_attributes.LegalPerson[array_legal[i]]
            });
        }

        for (let i = 0; i < array_representative.length; i++) {
            extensions['eidas:RequestedAttributes'].push({
                'eidas:RequestedAttribute': config_attributes.RepresentativeNaturalPerson[array_representative[i]]
            });
        }

        const auth_request = req.sp.create_authn_request_xml(idp, {
            extensions,
            saml_type: 'spid'
        });

        sp_states[auth_request.id] = get_state(req.url);
        sp_redirect_uris[auth_request.id] = get_redirect_uri(req.url);

        req.saml_auth_request = {
            xml: auth_request.request,
            // eslint-disable-next-line snakecase/snakecase
            postLocationUrl:
                'https://' + config.eidas.gateway_host + '/idm/applications/' + req.application.id + '/saml2/login',
            // eslint-disable-next-line snakecase/snakecase
            redirectLocationUrl:
                'https://' + config.eidas.gateway_host + '/idm/applications/' + req.application.id + '/saml2/login'
        };
        next();
    } else {
        next();
    }
};

// Function to generate SAML certificates
exports.generate_app_certificates = function (app_id, saml_credentials) {
    debug('--> generate_app_certificates');

    return new Promise((resolve, reject) => {
        const key_name = 'certs/applications/' + app_id + '-key.pem';
        const csr_name = 'certs/applications/' + app_id + '-csr.pem';
        const cert_name = 'certs/applications/' + app_id + '-cert.pem';

        const key = 'openssl genrsa -out ' + key_name + ' 2048';
        const csr =
            'openssl req -new -sha256 -key ' +
            key_name +
            ' -out ' +
            csr_name +
            ' -subj "/C=ES/ST=Madrid/L=Madrid/' +
            'O=' +
            saml_credentials.organization_name +
            '/OU=' +
            saml_credentials.organization_name +
            '/CN=' +
            saml_credentials.organization_url.replace(/(^\w+:|^)\/\//, '') +
            '"';

        const cert = 'openssl x509 -days 1095 -req -in ' + csr_name + ' -signkey ' + key_name + ' -out ' + cert_name;

        const create_certificates = key + ' && ' + csr + ' && ' + cert;
        exec(create_certificates, function (error) {
            if (error) {
                reject(error);
            } else {
                resolve();
            }
        });
    });
}
