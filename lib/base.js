/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * base (Base Metrics) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	Base["AV"] = require('./base-av');          // Base.AV(any):object
	Base["AC"] = require('./base-ac');          // Base.AC(any):object
	Base["PR"] = require('./base-pr');          // Base.PR(any):object
	Base["UI"] = require('./base-ui');          // Base.UI(any):object
	Base["S"] = require('./base-s');            // Base.S(any):object
	Base["C"] = require('./base-c');            // Base.C(any):object
	Base["I"] = require('./base-i');            // Base.I(any):object
	Base["A"] = require('./base-a');            // Base.A(any):object
	Base["prototype"]["constructor"] = Base;    // Base(any):object
	Base["prototype"]["getName"] = getName;     // Base#getName(void):string
	Base["prototype"]["setMetric"] = setMetric; // Base#setMetric(metric:object):this
	Base["prototype"]["getScore"] = getScore;   // Base#getScore(void):number
	Base["prototype"]["importVector"] = importVector; // Base#importVector(vector:string):this
	Base["prototype"]["getVector"] = getVector; // Base#getVector(void):string
	Base["prototype"]["getScoreImpactRow"] = getScoreImpactRow;             // Base#getScoreImpactRow(void):number
	Base["prototype"]["getScoreImpactWithScope"] = getScoreImpactWithScope; // Base#getScoreImpactWithScope(void):number
	Base["prototype"]["getScoreExploitability"] = getScoreExploitability;   // Base#getScoreExploitability(void):number

	/**
	 * Constructor
	 *
	 * @param {object} av : Attack Vector
	 * @param {object} ac : Attack Complexity
	 * @param {object} pr : Privileges Required
	 * @param {object} ui : User Interaction
	 * @param {object} s : Scope
	 * @param {object} c : Confidentiality Impact
	 * @param {object} i : Integrity Impact
	 * @param {object} a : Availability Impact
	 * @public
	 */
	function Base(av, ac, pr, ui, s, c, i, a) {

		//initialize
		if (typeof module === "object" && "exports" in module) {
			this.av = new Base.AV();
			this.ac = new Base.AC();
			this.pr = new Base.PR();
			this.ui = new Base.UI();
			this.s = new Base.S();
			this.c = new Base.C();
			this.i = new Base.I();
			this.a = new Base.A();
		} else {
			//for Browser (client side)
			this.av = new CVSS3_Base_AV();
			this.ac = new CVSS3_Base_AC();
			this.pr = new CVSS3_Base_PR();
			this.ui = new CVSS3_Base_UI();
			this.s = new CVSS3_Base_S();
			this.c = new CVSS3_Base_C();
			this.i = new CVSS3_Base_I();
			this.a = new CVSS3_Base_A();
		}

		//import metrics
		for (var cnt = 0; cnt < arguments.length; cnt++) {
			if (isString(arguments[cnt])) {
				this.importVector(arguments[cnt]);
			} else {
				this.setMetric(arguments[cnt]);
			}
		}
	}

	/**
	 * Method : set metric
	 *
	 * @param {object} metric : metric object
	 * @return this object
	 * @public
	 */
	function setMetric(metric) {
		if (!isNull(metric) && !isNull(metric.getName)) {
			switch (metric.getName()) {
			case 'AV' :
				this.av = metric;
				break;
			case 'AC' :
				this.ac = metric;
				break;
			case 'PR' :
				this.pr = metric;
				break;
			case 'UI' :
				this.ui = metric;
				break;
			case 'S' :
				this.s = metric;
				break;
			case 'C' :
				this.c = metric;
				break;
			case 'I' :
				this.i = metric;
				break;
			case 'A' :
				this.a = metric;
				break;
			default :
				break;
			}
		}
		return this;
	}

	function getName() {
		return "BaseMetrics";
	}

	/**
	 * Method : get score
	 *
	 * @return score of attack vector
	 * @public
	 */
	function getScore() {
		var scoreImpact = this.getScoreImpactWithScope();
		//console.log("getScoreImpactWithScope="+scoreImpact);
		var score = this.getScoreExploitability();
		//console.log("getScoreExploitability="+score);
		if (scoreImpact <= 0.0) {
			return 0.0;
		} else if (!this.s.isChange()) {
			//Scope: Unchanged
			score = Math.min((scoreImpact + score), 10.0);
		} else {
			//Scope: Changed
			score = Math.min(1.08 * (scoreImpact + score), 10.0);
		}
		score *= 10.0;
		score = Math.ceil(score); // round up
		return score / 10.0;
	}

	/**
	 * Method : get sub-score of impacts
	 *
	 * @return score of impacts
	 * @public
	 */
	function getScoreImpactRow() {
		return ( 1.0 - Math.abs( (1.0 - this.c.getScore()) * (1.0 - this.i.getScore()) * (1.0 - this.a.getScore()) ) );
	}

	/**
	 * Method : get sub-score of impacts with scope
	 *
	 * @return score of impacts with scope
	 * @public
	 */
	function getScoreImpactWithScope() {
		var score = this.getScoreImpactRow();
		//console.log("getScoreImpactRow="+score, "and Scope="+this.s.getVector());
		if (!this.s.isChange()) {
			//Scope: Unchanged
			return (6.42 * score);
		} else {
			//Scope: Changed
			return ((7.52 * Math.abs(score - 0.029)) - (3.25 * Math.pow(Math.abs(score - 0.02),15)));
		}
	}

	/**
	 * Method : get sub-score of exploitability
	 *
	 * @return score of exploitability
	 * @public
	 */
	function getScoreExploitability() {
		return (8.22 * this.av.getScore() * this.ac.getScore() * this.pr.getScore(this.s.isChange()) * this.ui.getScore());
	}

	/**
	 * Method : import vector
	 *
	 * @param {string} vector : vector
	 * @return this object
	 * @public
	 */
	function importVector(vector) {
		//console.log("vector="+vector);
		var metrics = vector.trim().split('/');
		for (var cnt = 0; cnt < metrics.length; cnt++) {
			var metric = metrics[cnt].trim().split(':');
			//console.log("name="+metric[0], "value="+metric[1]);
			if (cnt == 0) {
				if (metric[0].trim().toUpperCase() != 'CVSS' || metric[1].trim().toUpperCase() != '3.0') {
					// not CVSSv3 Vector
					return this;
				}
			} else {
				switch (metric[0].trim().toUpperCase()) {
				case 'AV' :
					this.av.setValue(metric[1].trim().toUpperCase());
					break;
				case 'AC' :
					this.ac.setValue(metric[1].trim().toUpperCase());
					break;
				case 'PR' :
					this.pr.setValue(metric[1].trim().toUpperCase());
					break;
				case 'UI' :
					this.ui.setValue(metric[1].trim().toUpperCase());
					break;
				case 'S' :
					this.s.setValue(metric[1].trim().toUpperCase());
					break;
				case 'C' :
					this.c.setValue(metric[1].trim().toUpperCase());
					break;
				case 'I' :
					this.i.setValue(metric[1].trim().toUpperCase());
					break;
				case 'A' :
					this.a.setValue(metric[1].trim().toUpperCase());
					break;
				default :
					break;
				}
			}
		}
		return this;
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of attack vector
	 * @public
	 */
	function getVector() {
		return 'CVSS:3.0' //prefix for CVSSv3
				+ '/' + this.av.getVector()
				+ '/' + this.ac.getVector()
				+ '/' + this.pr.getVector()
				+ '/' + this.ui.getVector()
				+ '/' + this.s.getVector()
				+ '/' + this.c.getVector()
				+ '/' + this.i.getVector()
				+ '/' + this.a.getVector();
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

	/**
	 * Method : string type (static)
	 *
	 * @param {object} obj : any object
	 * @return true if obj is string.
	 * @private
	 */
	function isString(obj) {
		return ((!isNull(obj)) && (typeof (obj) == 'string'));
	}

	// Exports
	if (typeof module === "object" && "exports" in module) {
		module["exports"] = Base;
	    return;
	}
	global["CVSS3_Base"] = Base;

})((this || 0).self || global);
