"use strict";

import { add_alert, add_session_alert, alert_ajax_failure, getUrlParameter, get_session_variable } from "./utilities.js";


$(function() {
	// Get URL parameter
	let email = get_session_variable("email");
	$("#email").val(email);
	$("#name").focus();
});

$("#submit").click(function() {
	$("#wait").modal();
});
$('#wait').on('shown.bs.modal', function (e) {
	let payload = {
		email: $("#email").val(),
		name: $("#name").val(),
		postal: $("#postal").val(),
	};
	console.log("Payload:");
	console.log(payload);
	$.post("/user/verify_identity", JSON.stringify(payload))
		.done(function( data ) {	
			console.log("Verify identity response data:");
			console.log(data);

			add_session_alert("Identification verification form submitted", "You have finished the registration process.", "success")

			window.location.href = "/profile.html";
		})
		.fail(function( data ) {
			console.log(data)
			alert_ajax_failure("Identity verification submission failed.", data, true);
		})
		.always(function() {
			$("#wait").modal("hide");
		});
});

// $('#postal').keypress(function (e) {
// 	if (e.which === 13) {
// 		$('#login').click();
// 		return false;
// 	}
// });
