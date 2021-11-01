"use strict";

import { add_alert, alert_ajax_failure, get_session_alert } from "./utilities.js";

$(function() {
	// Check for any alerts
	let alert = get_session_alert();
	if (alert) {
		add_alert(alert.title, alert.message, alert.style);
    }
});