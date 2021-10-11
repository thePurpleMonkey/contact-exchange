"use strict";

import { add_alert, alert_ajax_failure } from "./utilities.js";

// Enable tooltips
$("#email").tooltip({
	trigger: "focus",
	placement: "right"
});

$(function() {
	$("#email").focus();
});

$("#register").click(function() {
	// Verify passwords match
	if ($("#password").val() !== $("#confirm").val()) {
		add_alert("Passwords don't match!", "The passwords don't match. Please re-enter your password.", "danger", {replace_existing: true});
		$("#confirm").val("");
	} else {
		$("#wait").modal();
	}
});
$("#wait").on('shown.bs.modal', function (e) {
	$.post("/user/register", JSON.stringify({ email: $("#email").val(), password: $("#password").val() }) )
		.done(function( data ) {
			console.log("Register response data:");
			console.log(data);

			// Save the user_id
			try {
				window.localStorage.setItem("user_id", data.user_id);
			} catch (err) {
				console.log("Unable to set localStorage variable 'user_id'");
				console.log(err);
			}

			// Redirect to next URL
			let redirect = new URL(window.location.href).searchParams.get("redirect");
			if (redirect === null) {
				redirect = "/contacts.html";
			}
			redirect = decodeURIComponent(redirect);
			console.log("Redirecting to: " + redirect);
			window.location.href = redirect;
		})
		.fail(function( data ) {
			alert_ajax_failure("Registration failed.", data, true);
			console.log(data);
		})
		.always(function() {
			$("#wait").modal("hide");
		});
});

$('#confirm').keypress(function (e) {
	if (e.which === 13) {
		$('#register').click();
		return false;
	}
});