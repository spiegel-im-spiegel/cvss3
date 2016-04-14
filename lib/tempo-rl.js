/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * tempo-rl (Remediation Level) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	TempoRL["prototype"]["constructor"] = TempoRL; // TempoRL(value:string):object
	TempoRL["prototype"]["setValue"] = setValue;   // TempoRL#setValue(value:string):this
	TempoRL["prototype"]["getName"] = getName;     // TempoRL#getName(void):string
	TempoRL["prototype"]["getScore"] = getScore;   // TempoRL#getScore(void):number
	TempoRL["prototype"]["getVector"] = getVector; // TempoRL#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Remediation Level
	 * @public
	 */
	function TempoRL(value) {
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
		if (value == 'U' || value == 'W' || value == 'T' || value == 'O') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of Remediation Level
	 * @public
	 */
	function getName() {
		return 'RL';
	}

	/**
	 * Method : get score
	 *
	 * @return score of Remediation Level
	 * @public
	 */
	function getScore() {
		if (this.value == 'U') { //Unavailable
			return 1.00;
		} else if (this.value == 'W') { //Workaround
			return 0.97;
		} else if (this.value == 'T') { //Temporary Fix
			return 0.96;
		} else if (this.value == 'O') { //Official Fix
			return 0.95;
		} else { //Not Defined
			return 1.00
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of Remediation Level
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	// Exports
	if (typeof module === "object" && "exports" in module) {
		module["exports"] = TempoRL;
	}
	global["CVSS3_Temporal_RL"] = TempoRL;

})((this || 0).self || global);
