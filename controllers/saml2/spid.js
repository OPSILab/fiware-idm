const debug = require('debug')('idm:saml2_controller');
const models = require('../../models/models.js');
const config_service = require('../../lib/configService.js');
const config = config_service.get_config();
const spid_attributes = require('../../etc/spid/requested_attributes.json');
const saml_controller = require('./saml2');


exports.sp_states = {};
exports.sp_redirect_uris = {};

// GET /idm/applications/:application_id/step/spid -- Form to add SPID credentials to application
exports.step_new_spid_credentials = function (req, res) {
    debug('--> step_new_spid_credentials');
    res.render('saml2/step_create_spid_credentials', {
        application: req.application,
        spid_credentials: [],
        errors: [],
        csrf_token: req.csrfToken()
    });
};


// POST /idm/applications/:application_id/step/spid -- Create SPID credentials
exports.step_create_spid_credentials = function (req, res) {
    debug('--> step_create_spid_credentials');

    const spid_credentials = models.spid_credentials.build(req.body.spid_credentials);

    spid_credentials.oauth_client_id = req.application.id;

    spid_credentials.attributes_list = {
        // eslint-disable-next-line snakecase/snakecase
        name: "",
        familyName: "",
        email: ""
    };

    return spid_credentials
        .validate()
        .then(function () {
            return spid_credentials.save();
        })
        .then(function () {
            return saml_controller.generate_app_certificates(req.application.id, spid_credentials);
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
                text: ' Fail creating spid credentials.',
                type: 'warning'
            };

            return res.render('saml2/step_create_spid_credentials', {
                application: req.application,
                spid_credentials,
                errors: name_errors,
                csrf_token: req.csrfToken()
            });
        });
};


// GET /idm/applications/:application_id/edit/spid -- Render edit SPID credentials view
exports.edit_spid_credentials = function (req, res) {
    debug('--> edit_spid_credentials');

    res.render('saml2/edit_spid', {
        application: req.application,
        spid_credentials: req.spid_credentials,
        errors: [],
        csrf_token: req.csrfToken()
    });
};

// PUT /idm/applications/:application_id/edit/spid/info -- Update SPID Info
exports.update_spid_info = function (req, res) {
    debug('--> update_spid_info');

    const spid_credentials = models.spid_credentials.build(req.body.spid_credentials);
    spid_credentials.oauth_client_id = req.application.id;

    spid_credentials
        .validate()
        .then(function () {
            return models.spid_credentials.update(
                {
                    support_contact_person_name: req.body.spid_credentials.support_contact_person_name,
                    support_contact_person_surname: req.body.spid_credentials.support_contact_person_surname,
                    support_contact_person_email: req.body.spid_credentials.support_contact_person_email,
                    support_contact_person_telephone_number: req.body.spid_credentials.support_contact_person_telephone_number,
                    support_contact_person_company: req.body.spid_credentials.support_contact_person_company,
                    technical_contact_person_name: req.body.spid_credentials.technical_contact_person_name,
                    technical_contact_person_surname: req.body.spid_credentials.technical_contact_person_surname,
                    technical_contact_person_email: req.body.spid_credentials.technical_contact_person_email,
                    technical_contact_person_telephone_number:
                        req.body.spid_credentials.technical_contact_person_telephone_number,
                    technical_contact_person_company: req.body.spid_credentials.technical_contact_person_company,
                    organization_name: req.body.spid_credentials.organization_name,
                    organization_url: req.body.spid_credentials.organization_url,
                    organization_nif: req.body.spid_credentials.organization_nif,
                    sp_type: req.body.spid_credentials.sp_type
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
                text: ' SPID info updated successfully.',
                type: 'success'
            };
            res.redirect('/idm/applications/' + req.application.id);
        })
        .catch(function (error) {
            debug('Error: ', error);

            // Send message of warning of updating the application
            res.locals.message = {
                text: ' Unable to update SPID info.',
                type: 'warning'
            };
            req.body.spid_credentials.attributes_list = req.spid_credentials.attributes_list;

            const name_errors = [];
            if (error.errors && error.errors.length) {
                for (const i in error.errors) {
                    name_errors.push(error.errors[i].message);
                }
            }
            res.render('saml2/edit_spid', {
                application: req.application,
                spid_credentials: req.body.spid_credentials,
                errors: name_errors,
                csrf_token: req.csrfToken()
            });
        });
};

// PUT /idm/applications/:application_id/edit/spid/attributes -- Update SPID attributes
exports.update_spid_attributes = function (req, res) {
    debug('--> update_spid_attributes');

    const attributes_list = {
        "firstName": "",
        "familyName": "",
        "email": ""
    };

    for (const key of Object.keys(req.body)) {

        if (key !== '_csrf' && key !== '__proto__')
            attributes_list[key] = "";
    }


    //if (req.body.NaturalPerson) {
    //    const array_natural = Object.keys(req.body.NaturalPerson);
    //    for (let i = 0; i < array_natural.length; i++) {
    //        if (
    //            config_attributes_natural.includes(array_natural[i]) &&
    //            !attributes_list.NaturalPerson.includes(array_natural[i])
    //        ) {
    //            attributes_list.NaturalPerson.push(array_natural[i]);
    //        }
    //    }
    //}

    models.spid_credentials
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
                text: ' SPID attributes successfully updated.',
                type: 'success'
            };
            res.redirect('/idm/applications/' + req.application.id);
        })
        .catch(function (error) {
            debug('Error', error);
            req.session.message = {
                text: ' Fail update SPID attributes.',
                type: 'danger'
            };
            res.redirect('/idm/applications/' + req.application.id);
        });
};

// Create auth xml request for Spid to be send to the idp
exports.create_spid_auth_request = function (idp, req, res, next) {
    if (req.sp) {

        const extensions = {  
        };


        const auth_request = req.sp.create_authn_request_xml(idp, {
            extensions,
            saml_type : 'spid'
        });

        exports.sp_states[auth_request.id] = get_state(req.url);
        exports.sp_redirect_uris[auth_request.id] = get_redirect_uri(req.url);

        req.saml_auth_request = {
            xml: auth_request.request,
            // eslint-disable-next-line snakecase/snakecase
            postLocationUrl:
                'https://' + config.spid.gateway_host + '/idm/applications/' + req.application.id + '/saml2/login',
            // eslint-disable-next-line snakecase/snakecase
            redirectLocationUrl:
                'https://' + config.spid.gateway_host + '/idm/applications/' + req.application.id + '/saml2/login'
        };
        next();
    } else {
        next();
    }
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