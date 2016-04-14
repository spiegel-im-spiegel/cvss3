/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * env-ms (Modified Scope) module
 * @public
 */
(function(global) {
	"use strict;"

	// Required
	var BaseMetrics = require('./base');

	// Declaration
	EnvMS["prototype"]["constructor"] = EnvMS;   // EnvMS(value:string):object
	EnvMS["prototype"]["setValue"] = setValue;   // EnvMS#setValue(value:string):this
	EnvMS["prototype"]["getName"] = getName;     // EnvMS#getName(void):string
	EnvMS["prototype"]["getScore"] = getScore;   // EnvMS#getScore(void):number
	EnvMS["prototype"]["isChange"] = isChange;   // EnvMS#isChange(base:object):boolean
	EnvMS["prototype"]["getVector"] = getVector; // EnvMS#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Modified Scope
	 * @public
	 */
	function EnvMS(value) {
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
		if (value == 'C') {
			this.value = value;
		} else if (value == 'U') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of Modified Scope
	 * @public
	 */
	function getName() {
		return 'MS';
	}

	/**
	 * Method : get score (not used)
	 *
	 * @return score of Modified Scope
	 * @public
	 */
	function getScore() {
		return 0.0; //dummy
	}

	/**
	 * Method : Is Change ?
	 *
	 * @param {object} base : Base Metrics object
	 * @return true if value is "Change"
	 * @public
	 */
	function isChange(base) {
		if (this.value == 'C') { //Changed
			return true;
		} else if (this.value == 'U') { //Unchanged
			return false;
		} else { //Not Defined
			if (isNull(base)) {
				if (typeof module === "object" && "exports" in module) {
					base = new BaseMetrics();
				} else {
					//for Browser (client side)
					base = new CVSS3_Base();
				}
			}
			return base.s.isChange();
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of Modified Scope
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
		module["exports"] = EnvMS;
	}
	global["CVSS3_Environmental_MS"] = EnvMS;

})((this || 0).self || global);
