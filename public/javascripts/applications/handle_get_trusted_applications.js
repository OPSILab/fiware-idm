$(document).ready(function(){

	var applications = []
	var applications_filter = []

	var appTypingTimer;
	var appDoneTypingInterval = 500;

	var applications_table = $('div#trust_apps_content')

	var url = '/idm/applications/'+window.location.pathname.split('/')[3]+'/trusted_applications'

	load_applications(url)


	function htmlEntities(str) {
	    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
	}

	function load_applications(url, panel) {
		$('div#spinner_trust_apps').show('open')
		$.get(url, function(data, status) {
			if (data.applications.length > 0) {
				applications = data.applications
				applications_pagination(applications.length)
				create_applications_rows(applications.slice(0,5), applications_table)	
			} else {
				applications_table.find('.alert').show('open')
			}
			$('div#spinner_trust_apps').hide('close')
		})
	}

	function create_applications_rows(applications) {
		applications_table.children('.list-group-item').remove()

		for (var i = 0; i < applications.length; i++) {
			var application_row = $('#application_row_template').html();
            application_row = application_row.replace(/application_id/g, applications[i].id);
            application_row = application_row.replace(/application_image/g, applications[i].image);
            application_row = application_row.replace(/application_name/g, htmlEntities(applications[i].name));
            application_row = application_row.replace(/application_url/g, htmlEntities(applications[i].url));

            applications_table.append(application_row);
		}
	}

    $('div#trust_apps').find("input[name=trust_apps__filter__q]").bind("keyup input",function(e) {
        var filter = $(this).val();
        applications_filter = []
        
        clearTimeout(appTypingTimer);
        appTypingTimer = setTimeout(function() {
            for (var i = 0; i < applications.length; i++) {
                if (applications[i].name.includes(filter)) {
                    applications_filter.push(applications[i])
                }
            }
            create_applications_rows(applications_filter.slice(0,5))
            applications_pagination(applications_filter.length)
        }, appDoneTypingInterval);
    });

	function applications_pagination(max) {

		$('nav#trust_apps_pagination_container').bootpag({
		    total: Math.ceil(max/5),
		    page: 1,
		    maxVisible: 5,
		    leaps: true,
		    firstLastUse: true,
		    first: 'First',
		    last: 'Last',
		    wrapClass: 'pagination',
		    activeClass: 'active',
		    disabledClass: 'disabled',
		    nextClass: 'next',
		    prevClass: 'prev',
		    lastClass: 'last',
		    firstClass: 'first'
		}).on("page", function(event, num){
			var start = (num === 1) ? 0 : 5*(num - 1)
            var end = start + 5

            if (applications_filter.length <= 0) {
                create_applications_rows(applications.slice(start, end))
            } else {
                create_applications_rows(applications_filter.slice(start, end))
            }
		});
	}
});