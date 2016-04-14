/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * base-i (Modified Integrity Impact) module
 * @public
 */
(function(global) {
	"use strict;"

	// Required
	var BaseMetrics = require('./base');

	// Declaration
	EnvMI["prototype"]["constructor"] = EnvMI;   // EnvMI(value:string):object
	EnvMI["prototype"]["setValue"] = setValue;   // EnvMI#setValue(value:string):this
	EnvMI["prototype"]["getName"] = getName;     // EnvMI#getName(void):string
	EnvMI["prototype"]["getScore"] = getScore;   // EnvMI#getScore(base:object):number
	EnvMI["prototype"]["getVector"] = getVector; // EnvMI#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Modified Integrity Impact
	 * @public
	 */
	function EnvMI(value) {
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
	 * @return name of Modified Integrity Impact
	 * @public
	 */
	function getName() {
		return 'MI';
	}

	/**
	 * Method : get score
	 *
	 * @param {object} base : Base Metrics object
	 * @return score of Modified Integrity Impact
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
				if (typeof module === "object" && "exports" in module) {
					base = new BaseMetrics();
				} else {
					//for Browser (client side)
					base = new CVSS3_Base();
				}
			}
			return base.i.getScore();
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of Modified Integrity Impact
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
		module["exports"] = EnvMI;
    	return;
	}
	global["CVSS3_Environmental_MI"] = EnvMI;

})((this || 0).self || global);
