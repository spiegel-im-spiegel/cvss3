/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * env-mac (Modified Attack Complexity) module
 * @public
 */
(function(global) {
	"use strict;"

	// Required
	var BaseMetrics = require('./base');

	// Declaration
	EnvMAC["prototype"]["constructor"] = EnvMAC;  // EnvMAC(value:string):object
	EnvMAC["prototype"]["setValue"] = setValue;   // EnvMAC#setValue(value:string):this
	EnvMAC["prototype"]["getName"] = getName;     // EnvMAC#getName(void):string
	EnvMAC["prototype"]["getScore"] = getScore;   // EnvMAC#getScore(base:object):number
	EnvMAC["prototype"]["getVector"] = getVector; // EnvMAC#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Modified Attack Complexity
	 * @public
	 */
	function EnvMAC(value) {
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
		if (value == 'H' || value == 'L') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of Modified Attack Complexity
	 * @public
	 */
	function getName() {
		return 'MAC';
	}

	/**
	 * Method : get score
	 *
	 * @param {object} base : Base Metrics object
	 * @return score of Modified Attack Complexity
	 * @public
	 */
	function getScore(base) {
		if (this.value == 'L') { //Low
			return 0.77;
		} else if (this.value == 'H') { //High
			return 0.44;
		} else { //Not Defined
			if (isNull(base)) {
				if ("process" in global) {
					base = new BaseMetrics();
				} else {
					//for Browser (client side)
					base = new CVSS3_Base();
				}
			}
			return base.ac.getScore();
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of Modified Attack Complexity
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
		module["exports"] = EnvMAC;
	}
	global["CVSS3_Environmental_MAC"] = EnvMAC;

})((this || 0).self || global);
