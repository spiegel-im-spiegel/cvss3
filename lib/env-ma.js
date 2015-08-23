/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * base-i (Modified Availability Impact) module
 * @public
 */
(function(global) {
	"use strict;"

	// Required
	var BaseMetrics = require('./base');

	// Declaration
	EnvMA["prototype"]["constructor"] = EnvMA;   // EnvMA(value:string):object
	EnvMA["prototype"]["setValue"] = setValue;   // EnvMA#setValue(value:string):this
	EnvMA["prototype"]["getName"] = getName;     // EnvMA#getName(void):string
	EnvMA["prototype"]["getScore"] = getScore;   // EnvMA#getScore(base:object):number
	EnvMA["prototype"]["getVector"] = getVector; // EnvMA#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Modified Availability Impact
	 * @public
	 */
	function EnvMA(value) {
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
		if (value == 'H' || value == 'L' || value == 'N') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of Modified Availability Impact
	 * @public
	 */
	function getName() {
		return 'MA';
	}

	/**
	 * Method : get score
	 *
	 * @param {object} base : Base Metrics object
	 * @return score of Modified Availability Impact
	 * @public
	 */
	function getScore(base) {
		if (this.value == 'H') { //High
			return 0.56;
		} else if (this.value == 'L') { //Low
			return 0.22;
		} else if (this.value == 'N') { //None
			return 0.00;
		} else { //Not Defined
			if (isNull(base)) {
				if ("process" in global) {
					base = new BaseMetrics();
				} else {
					//for Browser (client side)
					base = new CVSS3_Base();
				}
			}
			return base.a.getScore();
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of Modified Availability Impact
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
	if ("process" in global) {
		module["exports"] = EnvMA;
	}
	global["CVSS3_Environmental_MA"] = EnvMA;

})((this || 0).self || global);
