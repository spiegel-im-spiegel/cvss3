/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * env-mui (Modified User Interaction) module
 * @public
 */
(function(global) {
	"use strict;"

	// Required
	var BaseMetrics = require('./base');

	// Declaration
	EnvMUI["prototype"]["constructor"] = EnvMUI;  // EnvMUI(value:string):object
	EnvMUI["prototype"]["setValue"] = setValue;   // EnvMUI#setValue(value:string):this
	EnvMUI["prototype"]["getName"] = getName;     // EnvMUI#getName(void):string
	EnvMUI["prototype"]["getScore"] = getScore;   // EnvMUI#getScore(base:object):number
	EnvMUI["prototype"]["getVector"] = getVector; // EnvMUI#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Modified User Interaction
	 * @public
	 */
	function EnvMUI(value) {
		this.setValue(value);
	}

	/**
	 * Method : set value of metric
	 *
	 * @param {string} value : value of metric
	 * @return this object
	 * @public
	 */
	function setValue(value) {
		this.value = 'X';
		if (value == 'N' || value == 'R') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of Modified User Interaction
	 * @public
	 */
	function getName() {
		return 'MUI';
	}

	/**
	 * Method : get score
	 *
	 * @param {object} base : Base Metrics object
	 * @return score of Modified User Interaction
	 * @public
	 */
	function getScore(base) {
		if (this.value == 'N') { //None
			return 0.85;
		} else if (this.value == 'R') { //Required
			return 0.62;
		} else { //Not Defined
			if (isNull(base)) {
				if (typeof module === "object" && "exports" in module) {
					base = new BaseMetrics();
				} else {
					//for Browser (client side)
					base = new CVSS3_Base();
				}
			}
			return base.ui.getScore();
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of Modified User Interaction
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	/**
	 * Method : null or undefined (static)
	 *
	 * @param {object} obj : any object
	 * @return true if obj is null or undefined.
	 * @private
	 */
	function isNull(obj) {
		return ((typeof (obj) == 'undefined') || (obj == null));
	}

	// Exports
	if (typeof module === "object" && "exports" in module) {
		module["exports"] = EnvMUI;
	}
	global["CVSS3_Environmental_MUI"] = EnvMUI;

})((this || 0).self || global);
