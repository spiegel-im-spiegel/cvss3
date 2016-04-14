/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * tempo-e (Exploit Code Maturity) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	TempoE["prototype"]["constructor"] = TempoE;  // TempoE(value:string):object
	TempoE["prototype"]["setValue"] = setValue;   // TempoE#setValue(value:string):this
	TempoE["prototype"]["getName"] = getName;     // TempoE#getName(void):string
	TempoE["prototype"]["getScore"] = getScore;   // TempoE#getScore(void):number
	TempoE["prototype"]["getVector"] = getVector; // TempoE#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Exploit Code Maturity
	 * @public
	 */
	function TempoE(value) {
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
		if (value == 'H' || value == 'F' || value == 'P' || value == 'U') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of Exploit Code Maturity
	 * @public
	 */
	function getName() {
		return 'E';
	}

	/**
	 * Method : get score
	 *
	 * @return score of Exploit Code Maturity
	 * @public
	 */
	function getScore() {
		if (this.value == 'H') { //High
			return 1.00;
		} else if (this.value == 'F') { //Functional
			return 0.97;
		} else if (this.value == 'P') { //Proof-of-Concept
			return 0.94;
		} else if (this.value == 'U') { //Unproven
			return 0.91;
		} else { //Not Defined
			return 1.00
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of Exploit Code Maturity
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	// Exports
	if (typeof module === "object" && "exports" in module) {
		module["exports"] = TempoE;
	}
	global["CVSS3_Temporal_E"] = TempoE;

})((this || 0).self || global);
