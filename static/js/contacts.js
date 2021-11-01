"use strict";

import { add_alert, alert_ajax_failure, get_session_alert } from "./utilities.js";

$(function() {
	// Check for any alerts
	let alert = get_session_alert();
	if (alert) {
		add_alert(alert.title, alert.message, alert.style);
    }

	// Load contacts
	refresh_contacts();
});

function refresh_contacts() {
    $.get("/contacts")
    .done(function(contacts) {
        console.log("Contacts:");
        console.log(contacts);

        // Add contacts to page
        $("#contacts").children().remove();
        if (contacts != null) {
            contacts.forEach(contact => {
				let a = $("<a>");
				a.addClass("list-group-item");
				a.addClass("list-group-item-action");
				a.attr("href", `/contact.html?contact_id=${encodeURIComponent(contact.contact_id)}`);
				a.text(contact.name);
				$("#contacts").append(a);
            });
        }
    })
    .fail(function(data) {
        alert_ajax_failure("Unable to get contacts!", data);
    });
}