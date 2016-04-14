/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * temoral (Temporal Metrics) module
 * @public
 */
(function(global) {
	"use strict;"

	// Required
	var BaseMetrics = require('./base');

	// Declaration
	Temporal["E"] = require('./tempo-e');                 // Temporal.E(any):object
	Temporal["RL"] = require('./tempo-rl');               // Temporal.RL(any):object
	Temporal["RC"] = require('./tempo-rc');               // Temporal.RC(any):object
	Temporal["prototype"]["constructor"] = Temporal;      // Temporal(any):object
	Temporal["prototype"]["getName"] = getName;           // Temporal#getName(void):string
	Temporal["prototype"]["setMetric"] = setMetric;       // Temporal#getName(metric:object):this
	Temporal["prototype"]["getScore"] = getScore;         // Temporal#getScore(base:object):number
	Temporal["prototype"]["importVector"] = importVector; // Temporal#importVector(vector:string):this
	Temporal["prototype"]["getVector"] = getVector;       // Temporal#getVector(base:object):string

	/**
	 * Constructor
	 *
	 * @param {object} e : Exploit Code Maturity
	 * @param {object} rl : Remediation Level
	 * @param {object} rc : Report Confidence
	 * @public
	 */
	function Temporal(e, rl, rc) {

		//initialize
		if (typeof module === "object" && "exports" in module) {
			this.e = new Temporal.E();
			this.rl = new Temporal.RL();
			this.rc = new Temporal.RC();
		} else {
			//for Browser (client side)
			this.e = new CVSS3_Temporal_E();
			this.rl = new CVSS3_Temporal_RL();
			this.rc = new CVSS3_Temporal_RC();
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
			case 'E' :
				this.e = metric;
				break;
			case 'RL' :
				this.rl = metric;
				break;
			case 'RC' :
				this.rc = metric;
				break;
			defult :
				break;
			}
		}
		return this;
	}

	function getName() {
		return "TemporalMetrics";
	}

	/**
	 * Method : get score
	 *
	 * @param {object} base : Base Metrics object
	 * @return score of attack vector
	 * @public
	 */
	function getScore(base) {
		if (isNull(base)) {
			if (typeof module === "object" && "exports" in module) {
				base = new BaseMetrics();
			} else {
				//for Browser (client side)
				base = new CVSS3_Base();
			}
		}

		var baseScore = base.getScore();
		if (baseScore == 0.00) {
			return baseScore;
		} else {
			var score = (baseScore * this.e.getScore() * this.rl.getScore() * this.rc.getScore()) * 10.0;
			score = Math.ceil(score); // round up
			return score / 10.0;
		}
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
				case 'E' :
					this.e.setValue(metric[1].trim().toUpperCase());
					break;

				case 'RL' :
					this.rl.setValue(metric[1].trim().toUpperCase());
					break;
				case 'RC' :
					this.rc.setValue(metric[1].trim().toUpperCase());
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
	function getVector(base) {
		if (isNull(base)) {
			if (typeof module === "object" && "exports" in module) {
				base = new BaseMetrics();
			} else {
				//for Browser (client side)
				base = new CVSS3_Base();
			}
		}
		return base.getVector()
				+ '/' + this.e.getVector()
				+ '/' + this.rl.getVector()
				+ '/' + this.rc.getVector();
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
		module["exports"] = Temporal;
	}
	global["CVSS3_Temporal"] = Temporal;

})((this || 0).self || global);
