/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * tempo-rc (Report Confidence) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	TempoRC["prototype"]["constructor"] = TempoRC; // TempoRC(value:string):object
	TempoRC["prototype"]["setValue"] = setValue;   // TempoRC#setValue(value:string):this
	TempoRC["prototype"]["getName"] = getName;     // TempoRC#getName(void):string
	TempoRC["prototype"]["getScore"] = getScore;   // TempoRC#getScore(void):number
	TempoRC["prototype"]["getVector"] = getVector; // TempoRC#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Report Confidence
	 * @public
	 */
	function TempoRC(value) {
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
		if (value == 'C' || value == 'R' || value == 'U') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of Report Confidence
	 * @public
	 */
	function getName() {
		return 'RC';
	}

	/**
	 * Method : get score
	 *
	 * @return score of Report Confidence
	 * @public
	 */
	function getScore() {
		if (this.value == 'C') { //Confirmed
			return 1.00;
		} else if (this.value == 'R') { //Reasonable
			return 0.96;
		} else if (this.value == 'U') { //Unknown
			return 0.92;
		} else { //Not Defined
			return 1.00
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of Report Confidence
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	// Exports
	if (typeof module === "object" && "exports" in module) {
		module["exports"] = TempoRC;
    	return;
	}
	global["CVSS3_Temporal_RC"] = TempoRC;

})((this || 0).self || global);
