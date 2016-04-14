/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * env-mpr (Modified Privileges Required) module
 * @public
 */
(function(global) {
	"use strict;"

	// Required
	var BaseMetrics = require('./base');

	// Declaration
	EnvMPR["prototype"]["constructor"] = EnvMPR;  // EnvMPR(value:string):object
	EnvMPR["prototype"]["setValue"] = setValue;   // EnvMPR#setValue(value:string):this
	EnvMPR["prototype"]["getName"] = getName;     // EnvMPR#getName(void):string
	EnvMPR["prototype"]["getScore"] = getScore;   // EnvMPR#getScore(s:object, base:object):number
	EnvMPR["prototype"]["getVector"] = getVector; // EnvMPR#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Modified Privileges Required
	 * @public
	 */
	function EnvMPR(value) {
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
		if (value == 'N' || value == 'L' || value == 'H') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of Modified Privileges Required
	 * @public
	 */
	function getName() {
		return 'MPR';
	}

	/**
	 * Method : get score
	 *
	 * @param {boolean} change : true if Scope is "Changed"
	 * @param {object} base : Base Metrics object
	 * @return score of Modified Privileges Required
	 * @public
	 */
	function getScore(change, base) {
		if (this.value == 'N') { //None
			return 0.85;
		} else if (this.value == 'L') { //Low
			if (change) {
				return 0.68;
			} else {
				return 0.62;
			}
		} else if (this.value == 'H') { //High
			if (change) {
				return 0.50;
			} else {
				return 0.27;
			}
		} else { //Not Define
			if (isNull(base)) {
				if (typeof module === "object" && "exports" in module) {
					base = new BaseMetrics();
				} else {
					//for Browser (client side)
					base = new CVSS3_Base();
				}
			}
			return base.pr.getScore(change);
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of Modified Privileges Required
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
		module["exports"] = EnvMPR;
	}
	global["CVSS3_Environmental_MPR"] = EnvMPR;

})((this || 0).self || global);
