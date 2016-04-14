/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * env-mav (Modified Attack Vector) module
 * @public
 */
(function(global) {
	"use strict;"

	// Required
	var BaseMetrics = require('./base');

	// Declaration
	EnvMAV["prototype"]["constructor"] = EnvMAV;  // EnvMAV(value:string):object
	EnvMAV["prototype"]["setValue"] = setValue;   // EnvMAV#setValue(value:string):this
	EnvMAV["prototype"]["getName"] = getName;     // EnvMAV#getName(void):string
	EnvMAV["prototype"]["getScore"] = getScore;   // EnvMAV#getScore(base:object):number
	EnvMAV["prototype"]["getVector"] = getVector; // EnvMAV#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Modified Attack Vector
	 * @public
	 */
	function EnvMAV(value) {
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
		if (value == 'P' || value == 'N' || value == 'A' || value == 'L') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of Modified Attack Vector
	 * @public
	 */
	function getName() {
		return 'MAV';
	}

	/**
	 * Method : get score
	 *
	 * @param {object} base : Base Metrics object
	 * @return score of Modified Attack Vector
	 * @public
	 */
	function getScore(base) {
		if (this.value == 'N') { //Network
			return 0.85;
		} else if (this.value == 'A') { //Adjacent Network
			return 0.62;
		} else if (this.value == 'L') { //Local
			return 0.55;
		} else if (this.value == 'P') { //Physical
			return 0.20;
		} else { //Not Defined
			if (isNull(base)) {
				if (typeof module === "object" && "exports" in module) {
					base = new BaseMetrics();
				} else {
					//for Browser (client side)
					base = new CVSS3_Base();
				}
			}
			return base.av.getScore();
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of Modified Attack Vector
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
		module["exports"] = EnvMAV;
	}
	global["CVSS3_Environmental_MAV"] = EnvMAV;

})((this || 0).self || global);
