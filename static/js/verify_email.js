"use strict";

import { add_alert, alert_ajax_failure } from "./utilities.js";

$(function() {
	let email;
	try {
		email = window.sessionStorage.getItem("email");
	} catch (err) {
		console.log("Unable to get email address from session storage.");
		console.log(err);
	}

	if (!email) {
		email = "Error retrieving email";
	}

	$("#email").text(email);
});

$("#verify_email_button").click(function() {
	$.post("/user/verify")
	.done(function(data) {
		add_alert("Verification email sent", "Your account verification email has been sent. Please allow up to 15 minutes for the email to arrive in your inbox. Check your spam messages if the email is not in your inbox.");
	})
	.fail(function(data) {
		alert_ajax_failure("Unable to send verification email.", data);
	});
});