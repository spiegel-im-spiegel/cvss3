/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * Env (Environmental Metrics) module
 * @public
 */
(function(global) {
	"use strict;"

	// Required
	var BaseMetrics = require('./base');
	var TemporalMetrics = require('./temporal');

	// Declaration
	Env["CR"] = require('./env-cr');           // Env.CR(any):object
	Env["IR"] = require('./env-ir');           // Env.IR(any):object
	Env["AR"] = require('./env-ar');           // Env.AR(any):object
	Env["MAV"] = require('./env-mav');         // Env.MAV(any):object
	Env["MAC"] = require('./env-mac');         // Env.MAC(any):object
	Env["MPR"] = require('./env-mpr');         // Env.MPR(any):object
	Env["MUI"] = require('./env-mui');         // Env.MUI(any):object
	Env["MS"] = require('./env-ms');           // Env.MS(any):object
	Env["MC"] = require('./env-mc');           // Env.MC(any):object
	Env["MI"] = require('./env-mi');           // Env.MI(any):object
	Env["MA"] = require('./env-ma');           // Env.MA(any):object
	Env["prototype"]["constructor"] = Env;     // Env(any):object
	Env["prototype"]["getName"] = getName;     // Env#getName(void):string
	Env["prototype"]["setMetric"] = setMetric; // Env#setMetric(metric:object):this
	Env["prototype"]["getScore"] = getScore;   // Env#getScore(base:object, temporal:object):number
	Env["prototype"]["importVector"] = importVector; // Env#importVector(vector:string):this
	Env["prototype"]["getVector"] = getVector; // Env#getVector(base:object):string
	Env["prototype"]["getScoreModifiedImpactRow"] = getScoreModifiedImpactRow;             // Env#getScoreModifiedImpactRow(base:object):number
	Env["prototype"]["getScoreModifiedImpactWithScope"] = getScoreModifiedImpactWithScope; // Env#getScoreModifiedImpactWithScope(base:object):number
	Env["prototype"]["getScoreModifiedExploitability"] = getScoreModifiedExploitability;   // Env#getScoreModifiedExploitability(base:object):number

	/**
	 * Constructor
	 *
	 * @param {object} cr : Confidentiality Requirement
	 * @param {object} ir : Integrity Requirement
	 * @param {object} ar : Availability Requirement
	 * @param {object} mav : Attack Vector
	 * @param {object} mac : Attack Complexity
	 * @param {object} mpr : Privileges Required
	 * @param {object} mui : User Interaction
	 * @param {object} ms : Scope
	 * @param {object} mc : Confidentiality Impact
	 * @param {object} mi : Integrity Impact
	 * @param {object} ma : Availability Impact
	 * @public
	 */
	function Env(cr, ci, ca, mav, mac, ms, mpr, mui, mc, mi, ma) {

		//initialize
		if (typeof module === "object" && "exports" in module) {
			this.cr = new Env.CR();
			this.ir = new Env.IR();
			this.ar = new Env.AR();
			this.mav = new Env.MAV();
			this.mac = new Env.MAC();
			this.mpr = new Env.MPR();
			this.mui = new Env.MUI();
			this.ms = new Env.MS();
			this.mc = new Env.MC();
			this.mi = new Env.MI();
			this.ma = new Env.MA();
		} else {
			//for Browser (client side)
			this.cr = new CVSS3_Environmental_CR();
			this.ir = new CVSS3_Environmental_IR();
			this.ar = new CVSS3_Environmental_AR();
			this.mav = new CVSS3_Environmental_MAV();
			this.mac = new CVSS3_Environmental_MAC();
			this.mpr = new CVSS3_Environmental_MPR();
			this.mui = new CVSS3_Environmental_MUI();
			this.ms = new CVSS3_Environmental_MS();
			this.mc = new CVSS3_Environmental_MC();
			this.mi = new CVSS3_Environmental_MI();
			this.ma = new CVSS3_Environmental_MA();
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
			case 'CR' :
				this.cr = metric;
				break;
			case 'IR' :
				this.ir = metric;
				break;
			case 'AR' :
				this.ar = metric;
				break;
			case 'MAV' :
				this.mav = metric;
				break;
			case 'MAC' :
				this.mac = metric;
				break;
			case 'MPR' :
				this.mpr = metric;
				break;
			case 'MUI' :
				this.mui = metric;
				break;
			case 'MS' :
				this.ms = metric;
				break;
			case 'MC' :
				this.mc = metric;
				break;
			case 'MI' :
				this.mi = metric;
				break;
			case 'MA' :
				this.ma = metric;
				break;
			default :
				break;
			}
		}
		return this;
	}

	function getName() {
		return "EnvironmentalMetrics";
	}

	/**
	 * Method : get score
	 *
	 * @param {object} base : Base Metrics object
	 * @return score of attack vector
	 * @public
	 */
	function getScore(base, temporal) {
		if (isNull(base)) {
			if (typeof module === "object" && "exports" in module) {
				base = new BaseMetrics();
			} else {
				//for Browser (client side)
				base = new CVSS3_Base();
			}
		}
		if (isNull(temporal)) {
			if (typeof module === "object" && "exports" in module) {
				temporal = new TemporalMetrics();
			} else {
				//for Browser (client side)
				temporal = new CVSS3_Temporal();
			}
		}

		var scoreImpact = this.getScoreModifiedImpactWithScope(base);
		//console.log("getScoreImpactWithScope="+scoreImpact);
		var baseScore = this.getScoreModifiedExploitability(base);
		//console.log("getScoreModifiedExploitability="+baseScore);
		if (scoreImpact <= 0.0) {
			return 0.0;
		} else if (!this.ms.isChange(base)) {
			//Scope: Unchanged
			baseScore = Math.min((scoreImpact + baseScore), 10.0);
		} else {
			//Scope: Changed
			baseScore = Math.min(1.08 * (scoreImpact + baseScore), 10.0);
		}
		baseScore *= 10.0;
		baseScore = Math.ceil(baseScore); // round up
		baseScore /= 10.0;
		//console.log("baseScore="+baseScore);

		var score = (baseScore * temporal.e.getScore() * temporal.rl.getScore() * temporal.rc.getScore()) * 10.0;
		score = Math.ceil(score); // round up
		return score / 10.0;
	}

	/**
	 * Method : get sub-score of modified impacts
	 *
	 * @param {object} base : Base Metrics object
	 * @return score of impacts
	 * @public
	 */
	function getScoreModifiedImpactRow(base) {
		return Math.min(( 1.0 - Math.abs( (1.0 - (this.mc.getScore(base) * this.cr.getScore())) * (1.0 - (this.mi.getScore(base) * this.ir.getScore())) * (1.0 - (this.ma.getScore(base) * this.ar.getScore())) ) ), 0.915);
	}

	/**
	 * Method : get sub-score of modified impacts with scope
	 *
	 * @param {object} base : Base Metrics object
	 * @return score of impacts with scope
	 * @public
	 */
	function getScoreModifiedImpactWithScope(base) {
		var score = this.getScoreModifiedImpactRow(base);
		//console.log("getScoreModifiedImpactRow="+score, "and Scope="+this.ms.getVector());
		if (!this.ms.isChange(base)) {
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
	function getScoreModifiedExploitability(base) {
		return (8.22 * this.mav.getScore(base) * this.mac.getScore(base) * this.mpr.getScore(this.ms.isChange(base), base) * this.mui.getScore(base));
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
				case 'CR' :
					this.cr.setValue(metric[1].trim().toUpperCase());
					break;
				case 'IR' :
					this.ir.setValue(metric[1].trim().toUpperCase());
					break;
				case 'AR' :
					this.ar.setValue(metric[1].trim().toUpperCase());
					break;
				case 'MAV' :
					this.mav.setValue(metric[1].trim().toUpperCase());
					break;
				case 'MAC' :
					this.mac.setValue(metric[1].trim().toUpperCase());
					break;
				case 'MPR' :
					this.mpr.setValue(metric[1].trim().toUpperCase());
					break;
				case 'MUI' :
					this.mui.setValue(metric[1].trim().toUpperCase());
					break;
				case 'MS' :
					this.ms.setValue(metric[1].trim().toUpperCase());
					break;
				case 'MC' :
					this.mc.setValue(metric[1].trim().toUpperCase());
					break;
				case 'MI' :
					this.mi.setValue(metric[1].trim().toUpperCase());
					break;
				case 'MA' :
					this.ma.setValue(metric[1].trim().toUpperCase());
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
	function getVector(base, temporal) {
		var vector = "";
		if (isNull(base)) {
			if (typeof module === "object" && "exports" in module) {
				base = new BaseMetrics();
			} else {
				//for Browser (client side)
				base = new CVSS3_Base();
			}
		}
		if (isNull(temporal)) {
			if (typeof module === "object" && "exports" in module) {
				temporal = new TemporalMetrics();
			} else {
				//for Browser (client side)
				temporal = new CVSS3_Temporal();
			}
		}
		return temporal.getVector(base)
				+ '/' + this.cr.getVector()
				+ '/' + this.ir.getVector()
				+ '/' + this.ar.getVector()
				+ '/' + this.mav.getVector()
				+ '/' + this.mac.getVector()
				+ '/' + this.mpr.getVector()
				+ '/' + this.mui.getVector()
				+ '/' + this.ms.getVector()
				+ '/' + this.mc.getVector()
				+ '/' + this.mi.getVector()
				+ '/' + this.ma.getVector();
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
		module["exports"] = Env;
	}
	global["CVSS3_Environmental"] = Env;

})((this || 0).self || global);
