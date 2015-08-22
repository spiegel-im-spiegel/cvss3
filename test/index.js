var should = require('should');

var CVSS3 = require('../');

describe('cvss3', function () {

	describe('base', function () {

		describe('base-av', function () {

			var testSetAV = [
				{"value": 'N', "score": 0.85},
				{"value": 'A', "score": 0.62},
				{"value": 'L', "score": 0.55},
				{"value": 'P', "score": 0.20}
			];
			var nameAV = 'AV';

			it('Test Attack Vector : '+testSetAV[0].value, function () {
				var value = testSetAV[0].value;
				var score = testSetAV[0].score;
				var baseAv = new CVSS3.BaseMetrics.AV(value);
				baseAv.getName().should.equal(nameAV);
				baseAv.getVector().should.equal(nameAV+':'+value);
				baseAv.getScore().should.equal(score);
			});

			it('Test Attack Vector : '+testSetAV[1].value, function () {
				var value = testSetAV[1].value;
				var score = testSetAV[1].score;
				var baseAv = new CVSS3.BaseMetrics.AV(value);
				baseAv.getName().should.equal(nameAV);
				baseAv.getVector().should.equal(nameAV+':'+value);
				baseAv.getScore().should.equal(score);
			});

			it('Test Attack Vector : '+testSetAV[2].value, function () {
				var value = testSetAV[2].value;
				var score = testSetAV[2].score;
				var baseAv = new CVSS3.BaseMetrics.AV(value);
				baseAv.getName().should.equal(nameAV);
				baseAv.getVector().should.equal(nameAV+':'+value);
				baseAv.getScore().should.equal(score);
			});

			it('Test Attack Vector : '+testSetAV[3].value, function () {
				var value = testSetAV[3].value;
				var score = testSetAV[3].score;
				var baseAv = new CVSS3.BaseMetrics.AV(value);
				baseAv.getName().should.equal(nameAV);
				baseAv.getVector().should.equal(nameAV+':'+value);
				baseAv.getScore().should.equal(score);
			});

			it('Test Attack Vector : null', function () {
				var value = testSetAV[3].value;
				var score = testSetAV[3].score;
				var baseAv = new CVSS3.BaseMetrics.AV(null);
				baseAv.getName().should.equal(nameAV);
				baseAv.getVector().should.equal(nameAV+':'+value);
				baseAv.getScore().should.equal(score);
			});

			it('Test Attack Vector : undefined', function () {
				var value = testSetAV[3].value;
				var score = testSetAV[3].score;
				var baseAv = new CVSS3.BaseMetrics.AV(); //no argument
				baseAv.getName().should.equal(nameAV);
				baseAv.getVector().should.equal(nameAV+':'+value);
				baseAv.getScore().should.equal(score);
			});

		});

		describe('base-ac', function () {

			var testSetAC = [
				{"value": 'L', "score": 0.77},
				{"value": 'H', "score": 0.44},
			];
			var nameAC = 'AC';

			it('Test Attack Complexity : '+testSetAC[0].value, function () {
				var value = testSetAC[0].value;
				var score = testSetAC[0].score;
				var baseAC = new CVSS3.BaseMetrics.AC(value);
				baseAC.getName().should.equal(nameAC);
				baseAC.getVector().should.equal(nameAC+':'+value);
				baseAC.getScore().should.equal(score);
			});

			it('Test Attack Complexity : '+testSetAC[1].value, function () {
				var value = testSetAC[1].value;
				var score = testSetAC[1].score;
				var baseAC = new CVSS3.BaseMetrics.AC(value);
				baseAC.getName().should.equal(nameAC);
				baseAC.getVector().should.equal(nameAC+':'+value);
				baseAC.getScore().should.equal(score);
			});

			it('Test Attack Complexity : null', function () {
				var value = testSetAC[1].value;
				var score = testSetAC[1].score;
				var baseAC = new CVSS3.BaseMetrics.AC(null);
				baseAC.getName().should.equal(nameAC);
				baseAC.getVector().should.equal(nameAC+':'+value);
				baseAC.getScore().should.equal(score);
			});

			it('Test Attack Complexity : undefined', function () {
				var value = testSetAC[1].value;
				var score = testSetAC[1].score;
				var baseAC = new CVSS3.BaseMetrics.AC(); //no argument
				baseAC.getName().should.equal(nameAC);
				baseAC.getVector().should.equal(nameAC+':'+value);
				baseAC.getScore().should.equal(score);
			});

		});

		describe('base-s', function () {

			var testSetS = [
				{"value": 'C', "score": 0.0},
				{"value": 'U', "score": 0.0},
			];
			var nameS = 'S';

			it('Test Scope : '+testSetS[0].value, function () {
				var value = testSetS[0].value;
				var score = testSetS[0].score;
				var baseS = new CVSS3.BaseMetrics.S(value);
				baseS.getName().should.equal(nameS);
				baseS.getVector().should.equal(nameS+':'+value);
				baseS.getScore().should.equal(score);
			});

			it('Test Scope : '+testSetS[1].value, function () {
				var value = testSetS[1].value;
				var score = testSetS[1].score;
				var baseS = new CVSS3.BaseMetrics.S(value);
				baseS.getName().should.equal(nameS);
				baseS.getVector().should.equal(nameS+':'+value);
				baseS.getScore().should.equal(score);
			});

			it('Test Scope : null', function () {
				var value = testSetS[1].value;
				var score = testSetS[1].score;
				var baseS = new CVSS3.BaseMetrics.S(null);
				baseS.getName().should.equal(nameS);
				baseS.getVector().should.equal(nameS+':'+value);
				baseS.getScore().should.equal(score);
			});

			it('Test Scope : undefined', function () {
				var value = testSetS[1].value;
				var score = testSetS[1].score;
				var baseS = new CVSS3.BaseMetrics.S(); //no argument
				baseS.getName().should.equal(nameS);
				baseS.getVector().should.equal(nameS+':'+value);
				baseS.getScore().should.equal(score);
			});

		});

		describe('base-pr', function () {

			var testSetPR1 = [
				{"value": 'N', "score": 0.85},
				{"value": 'L', "score": 0.62},
				{"value": 'H', "score": 0.27}
			];
			var namePR = 'PR';
			var scopeU = new CVSS3.BaseMetrics.S('U');

			it('Test Privileges Required : '+testSetPR1[0].value+' (Scope U)', function () {
				var value = testSetPR1[0].value;
				var score = testSetPR1[0].score;
				var basePR = new CVSS3.BaseMetrics.PR(value);
				basePR.getName().should.equal(namePR);
				basePR.getVector().should.equal(namePR+':'+value);
				basePR.getScore(scopeU).should.equal(score);
				basePR.getScore(null).should.equal(score);
				basePR.getScore().should.equal(score);
			});

			it('Test Privileges Required : '+testSetPR1[1].value+' (Scope U)', function () {
				var value = testSetPR1[1].value;
				var score = testSetPR1[1].score;
				var basePR = new CVSS3.BaseMetrics.PR(value);
				basePR.getName().should.equal(namePR);
				basePR.getVector().should.equal(namePR+':'+value);
				basePR.getScore(scopeU).should.equal(score);
				basePR.getScore(null).should.equal(score);
				basePR.getScore().should.equal(score);
			});

			it('Test Privileges Required : '+testSetPR1[2].value+' (Scope U)', function () {
				var value = testSetPR1[2].value;
				var score = testSetPR1[2].score;
				var basePR = new CVSS3.BaseMetrics.PR(value);
				basePR.getName().should.equal(namePR);
				basePR.getVector().should.equal(namePR+':'+value);
				basePR.getScore(scopeU).should.equal(score);
				basePR.getScore(null).should.equal(score);
				basePR.getScore().should.equal(score);
			});

			it('Test Privileges Required : null'+' (Scope U)', function () {
				var value = testSetPR1[2].value;
				var score = testSetPR1[2].score;
				var basePR = new CVSS3.BaseMetrics.PR(null);
				basePR.getName().should.equal(namePR);
				basePR.getVector().should.equal(namePR+':'+value);
				basePR.getScore(scopeU).should.equal(score);
				basePR.getScore(null).should.equal(score);
				basePR.getScore().should.equal(score);
			});

			it('Test Privileges Required : undefined'+' (Scope U)', function () {
				var value = testSetPR1[2].value;
				var score = testSetPR1[2].score;
				var basePR = new CVSS3.BaseMetrics.PR(); //no argument
				basePR.getName().should.equal(namePR);
				basePR.getVector().should.equal(namePR+':'+value);
				basePR.getScore(scopeU).should.equal(score);
				basePR.getScore(null).should.equal(score);
				basePR.getScore().should.equal(score);
			});

			var testSetPR2 = [
				{"value": 'N', "score": 0.85},
				{"value": 'L', "score": 0.68},
				{"value": 'H', "score": 0.50}
			];
			var scopeC = new CVSS3.BaseMetrics.S('C');

			it('Test Privileges Required : '+testSetPR2[0].value+' (Scope C)', function () {
				var value = testSetPR2[0].value;
				var score = testSetPR2[0].score;
				var basePR = new CVSS3.BaseMetrics.PR(value);
				basePR.getName().should.equal(namePR);
				basePR.getVector().should.equal(namePR+':'+value);
				basePR.getScore(scopeC).should.equal(score);
			});

			it('Test Privileges Required : '+testSetPR2[1].value+' (Scope C)', function () {
				var value = testSetPR2[1].value;
				var score = testSetPR2[1].score;
				var basePR = new CVSS3.BaseMetrics.PR(value);
				basePR.getName().should.equal(namePR);
				basePR.getVector().should.equal(namePR+':'+value);
				basePR.getScore(scopeC).should.equal(score);
			});

			it('Test Privileges Required : '+testSetPR2[2].value+' (Scope C)', function () {
				var value = testSetPR2[2].value;
				var score = testSetPR2[2].score;
				var basePR = new CVSS3.BaseMetrics.PR(value);
				basePR.getName().should.equal(namePR);
				basePR.getVector().should.equal(namePR+':'+value);
				basePR.getScore(scopeC).should.equal(score);
			});

			it('Test Privileges Required : null'+' (Scope C)', function () {
				var value = testSetPR2[2].value;
				var score = testSetPR2[2].score;
				var basePR = new CVSS3.BaseMetrics.PR(null);
				basePR.getName().should.equal(namePR);
				basePR.getVector().should.equal(namePR+':'+value);
				basePR.getScore(scopeC).should.equal(score);
			});

			it('Test Privileges Required : undefined'+' (Scope C)', function () {
				var value = testSetPR2[2].value;
				var score = testSetPR2[2].score;
				var basePR = new CVSS3.BaseMetrics.PR(); //no argument
				basePR.getName().should.equal(namePR);
				basePR.getVector().should.equal(namePR+':'+value);
				basePR.getScore(scopeC).should.equal(score);
			});

		});

		describe('base-ui', function () {

			var testSetUI = [
				{"value": 'N', "score": 0.85},
				{"value": 'R', "score": 0.62}
			];
			var nameUI = 'UI';

			it('Test User Interaction : '+testSetUI[0].value, function () {
				var value = testSetUI[0].value;
				var score = testSetUI[0].score;
				var baseUI = new CVSS3.BaseMetrics.UI(value);
				baseUI.getName().should.equal(nameUI);
				baseUI.getVector().should.equal(nameUI+':'+value);
				baseUI.getScore().should.equal(score);
			});

			it('Test User Interaction : '+testSetUI[1].value, function () {
				var value = testSetUI[1].value;
				var score = testSetUI[1].score;
				var baseUI = new CVSS3.BaseMetrics.UI(value);
				baseUI.getName().should.equal(nameUI);
				baseUI.getVector().should.equal(nameUI+':'+value);
				baseUI.getScore().should.equal(score);
			});

			it('Test User Interaction : null', function () {
				var value = testSetUI[1].value;
				var score = testSetUI[1].score;
				var baseUI = new CVSS3.BaseMetrics.UI(null);
				baseUI.getName().should.equal(nameUI);
				baseUI.getVector().should.equal(nameUI+':'+value);
				baseUI.getScore().should.equal(score);
			});

			it('Test User Interaction : undefined', function () {
				var value = testSetUI[1].value;
				var score = testSetUI[1].score;
				var baseUI = new CVSS3.BaseMetrics.UI(); //no argument
				baseUI.getName().should.equal(nameUI);
				baseUI.getVector().should.equal(nameUI+':'+value);
				baseUI.getScore().should.equal(score);
			});

		});

		describe('base-c', function () {

			var testSetC = [
				{"value": 'H', "score": 0.56},
				{"value": 'L', "score": 0.22},
				{"value": 'N', "score": 0.00}
			];
			var nameC = 'C';

			it('Test Confidentiality Impact : '+testSetC[0].value, function () {
				var value = testSetC[0].value;
				var score = testSetC[0].score;
				var baseC = new CVSS3.BaseMetrics.C(value);
				baseC.getName().should.equal(nameC);
				baseC.getVector().should.equal(nameC+':'+value);
				baseC.getScore().should.equal(score);
			});

			it('Test Confidentiality Impact : '+testSetC[1].value, function () {
				var value = testSetC[1].value;
				var score = testSetC[1].score;
				var baseC = new CVSS3.BaseMetrics.C(value);
				baseC.getName().should.equal(nameC);
				baseC.getVector().should.equal(nameC+':'+value);
				baseC.getScore().should.equal(score);
			});

			it('Test Confidentiality Impact : '+testSetC[2].value, function () {
				var value = testSetC[2].value;
				var score = testSetC[2].score;
				var baseC = new CVSS3.BaseMetrics.C(value);
				baseC.getName().should.equal(nameC);
				baseC.getVector().should.equal(nameC+':'+value);
				baseC.getScore().should.equal(score);
			});

			it('Test Confidentiality Impact : null', function () {
				var value = testSetC[2].value;
				var score = testSetC[2].score;
				var baseC = new CVSS3.BaseMetrics.C(null);
				baseC.getName().should.equal(nameC);
				baseC.getVector().should.equal(nameC+':'+value);
				baseC.getScore().should.equal(score);
			});

			it('Test Confidentiality Impact : undefined', function () {
				var value = testSetC[2].value;
				var score = testSetC[2].score;
				var baseC = new CVSS3.BaseMetrics.C(); //no argument
				baseC.getName().should.equal(nameC);
				baseC.getVector().should.equal(nameC+':'+value);
				baseC.getScore().should.equal(score);
			});

		});

		describe('base-i', function () {

			var testSetI = [
				{"value": 'H', "score": 0.56},
				{"value": 'L', "score": 0.22},
				{"value": 'N', "score": 0.00}
			];
			var nameI = 'I';

			it('Test Integrity Impact : '+testSetI[0].value, function () {
				var value = testSetI[0].value;
				var score = testSetI[0].score;
				var baseI = new CVSS3.BaseMetrics.I(value);
				baseI.getName().should.equal(nameI);
				baseI.getVector().should.equal(nameI+':'+value);
				baseI.getScore().should.equal(score);
			});

			it('Test Integrity Impact : '+testSetI[1].value, function () {
				var value = testSetI[1].value;
				var score = testSetI[1].score;
				var baseI = new CVSS3.BaseMetrics.I(value);
				baseI.getName().should.equal(nameI);
				baseI.getVector().should.equal(nameI+':'+value);
				baseI.getScore().should.equal(score);
			});

			it('Test Integrity Impact : '+testSetI[2].value, function () {
				var value = testSetI[2].value;
				var score = testSetI[2].score;
				var baseI = new CVSS3.BaseMetrics.I(value);
				baseI.getName().should.equal(nameI);
				baseI.getVector().should.equal(nameI+':'+value);
				baseI.getScore().should.equal(score);
			});

			it('Test Integrity Impact : null', function () {
				var value = testSetI[2].value;
				var score = testSetI[2].score;
				var baseI = new CVSS3.BaseMetrics.I(null);
				baseI.getName().should.equal(nameI);
				baseI.getVector().should.equal(nameI+':'+value);
				baseI.getScore().should.equal(score);
			});

			it('Test Integrity Impact : undefined', function () {
				var value = testSetI[2].value;
				var score = testSetI[2].score;
				var baseI = new CVSS3.BaseMetrics.I(); //no argument
				baseI.getName().should.equal(nameI);
				baseI.getVector().should.equal(nameI+':'+value);
				baseI.getScore().should.equal(score);
			});

		});

		describe('base-a', function () {

			var testSetA = [
				{"value": 'H', "score": 0.56},
				{"value": 'L', "score": 0.22},
				{"value": 'N', "score": 0.00}
			];
			var nameA = 'A';

			it('Test Integrity Impact : '+testSetA[0].value, function () {
				var value = testSetA[0].value;
				var score = testSetA[0].score;
				var baseA = new CVSS3.BaseMetrics.A(value);
				baseA.getName().should.equal(nameA);
				baseA.getVector().should.equal(nameA+':'+value);
				baseA.getScore().should.equal(score);
			});

			it('Test Integrity Impact : '+testSetA[1].value, function () {
				var value = testSetA[1].value;
				var score = testSetA[1].score;
				var baseA = new CVSS3.BaseMetrics.A(value);
				baseA.getName().should.equal(nameA);
				baseA.getVector().should.equal(nameA+':'+value);
				baseA.getScore().should.equal(score);
			});

			it('Test Integrity Impact : '+testSetA[2].value, function () {
				var value = testSetA[2].value;
				var score = testSetA[2].score;
				var baseA = new CVSS3.BaseMetrics.A(value);
				baseA.getName().should.equal(nameA);
				baseA.getVector().should.equal(nameA+':'+value);
				baseA.getScore().should.equal(score);
			});

			it('Test Integrity Impact : null', function () {
				var value = testSetA[2].value;
				var score = testSetA[2].score;
				var baseA = new CVSS3.BaseMetrics.A(null);
				baseA.getName().should.equal(nameA);
				baseA.getVector().should.equal(nameA+':'+value);
				baseA.getScore().should.equal(score);
			});

			it('Test Integrity Impact : undefined', function () {
				var value = testSetA[2].value;
				var score = testSetA[2].score;
				var baseA = new CVSS3.BaseMetrics.A(); //no argument
				baseA.getName().should.equal(nameA);
				baseA.getVector().should.equal(nameA+':'+value);
				baseA.getScore().should.equal(score);
			});

		});

		it('Test Base Metrics : Input "Attack Vector" metric', function () {
			var base = new CVSS3.BaseMetrics(new CVSS3.BaseMetrics.AV('N'));
			base.av.getVector().should.equal('AV:N');
			base.av.getScore().should.equal(0.85);
		});

		it('Test Base Metrics : Input "Attack Complexity" metric', function () {
			var base = new CVSS3.BaseMetrics(new CVSS3.BaseMetrics.AC('L'));
			base.ac.getVector().should.equal('AC:L');
			base.ac.getScore().should.equal(0.77);
		});

		it('Test Base Metrics : Input "Scope" metric', function () {
			var base = new CVSS3.BaseMetrics(new CVSS3.BaseMetrics.S('C'));
			base.s.getVector().should.equal('S:C');
			base.s.getScore().should.equal(0.00);
		});

		it('Test Base Metrics : Input "Privileges Required" metric', function () {
			var base = new CVSS3.BaseMetrics(new CVSS3.BaseMetrics.PR('N'));
			base.pr.getVector().should.equal('PR:N');
			base.pr.getScore(new CVSS3.BaseMetrics.S()).should.equal(0.85);
		});

		it('Test Base Metrics : Input "User Interaction" metric', function () {
			var base = new CVSS3.BaseMetrics(new CVSS3.BaseMetrics.UI('N'));
			base.ui.getVector().should.equal('UI:N');
			base.ui.getScore().should.equal(0.85);
		});

		it('Test Base Metrics : Input "Confidentiality Impact" metric', function () {
			var base = new CVSS3.BaseMetrics(new CVSS3.BaseMetrics.C('H'));
			base.c.getVector().should.equal('C:H');
			base.c.getScore().should.equal(0.56);
		});

		it('Test Base Metrics : Input "Integrity Impact" metric', function () {
			var base = new CVSS3.BaseMetrics(new CVSS3.BaseMetrics.I('H'));
			base.i.getVector().should.equal('I:H');
			base.i.getScore().should.equal(0.56);
		});

		it('Test Base Metrics : Input "Integrity Impact" metric', function () {
			var base = new CVSS3.BaseMetrics(new CVSS3.BaseMetrics.I('L'));
			base.i.getVector().should.equal('I:L');
			base.i.getScore().should.equal(0.22);
		});

		it('Test Base Metrics : Input "Availability Impact" metric', function () {
			var base = new CVSS3.BaseMetrics(new CVSS3.BaseMetrics.A('H'));
			base.a.getVector().should.equal('A:H');
			base.a.getScore().should.equal(0.56);
		});

		it('Test Base Metrics : Input all metric', function () {
			var vector_cve_2013_1937 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";
			var base = new CVSS3.BaseMetrics(new CVSS3.BaseMetrics.AV('N')
												,new CVSS3.BaseMetrics.AC('L')
												,new CVSS3.BaseMetrics.PR('N')
												,new CVSS3.BaseMetrics.UI('R')
												,new CVSS3.BaseMetrics.S('C')
												,new CVSS3.BaseMetrics.C('L')
												,new CVSS3.BaseMetrics.I('L')
												,new CVSS3.BaseMetrics.A('N'));
			base.getName().should.equal("BaseMetrics");
			base.getVector().should.equal(vector_cve_2013_1937);
			base.getScore().should.equal(6.1);
		});

		it('Test Base Metrics : Undefined', function () {
			var base = new CVSS3.BaseMetrics();
			var vector_zero = "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N";
			base.getVector().should.equal(vector_zero);
			base.getScore().should.equal(0.0);
		});

		it('Test Base Metrics : CVE-2013-1937', function () {
			var vector_cve_2013_1937 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2013_1937);
			base.getVector().should.equal(vector_cve_2013_1937);
			base.getScore().should.equal(6.1);
		});
		it('Test Base Metrics : CVE-2013-1937 not CVSSv3', function () {
			var vector_cve_2013_1937e = "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2013_1937e);
			base.getScore().should.equal(0.0);
		});


		it('Test Base Metrics : CVE-2013-0375', function () {
			var vector_cve_2013_0375 = "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2013_0375);
			base.getVector().should.equal(vector_cve_2013_0375);
			base.getScore().should.equal(6.4);
		});

		it('Test Base Metrics : CVE-2014-3566', function () {
			var vector_cve_2014_3566 = "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2014_3566);
			base.getVector().should.equal(vector_cve_2014_3566);
			base.getScore().should.equal(3.1);
		});

		it('Test Base Metrics : CVE-2012-1516', function () {
			var vector_cve_2012_1516 = "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2012_1516);
			base.getVector().should.equal(vector_cve_2012_1516);
			base.getScore().should.equal(9.9);
		});

		it('Test Base Metrics : CVE-2009-0783', function () {
			var vector_cve_2009_0783 = "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2009_0783);
			base.getVector().should.equal(vector_cve_2009_0783);
			base.getScore().should.equal(4.2);
		});

		it('Test Base Metrics : CVE-2012-0384', function () {
			var vector_cve_2012_0384 = "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2012_0384);
			base.getVector().should.equal(vector_cve_2012_0384);
			base.getScore().should.equal(8.8);
		});

		it('Test Base Metrics : CVE-2015-1098', function () {
			var vector_cve_2015_1098 = "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2015_1098);
			base.getVector().should.equal(vector_cve_2015_1098);
			base.getScore().should.equal(7.8);
		});

		it('Test Base Metrics : CVE-2014-0160', function () {
			var vector_cve_2014_0160 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2014_0160);
			base.getVector().should.equal(vector_cve_2014_0160);
			base.getScore().should.equal(7.5);
		});

		it('Test Base Metrics : CVE-2014-6271', function () {
			var vector_cve_2014_6271 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2014_6271);
			base.getVector().should.equal(vector_cve_2014_6271);
			base.getScore().should.equal(9.8);
		});

		it('Test Base Metrics : CVE-2008-1447', function () {
			var vector_cve_2008_1447 = "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2008_1447);
			base.getVector().should.equal(vector_cve_2008_1447);
			base.getScore().should.equal(6.8);
		});

		it('Test Base Metrics : CVE-2014-2005', function () {
			var vector_cve_2014_2005 = "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2014_2005);
			base.getVector().should.equal(vector_cve_2014_2005);
			base.getScore().should.equal(6.8);
		});

		it('Test Base Metrics : CVE-2010-0467', function () {
			var vector_cve_2010_0467 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2010_0467);
			base.getVector().should.equal(vector_cve_2010_0467);
			base.getScore().should.equal(5.8);
		});

		it('Test Base Metrics : CVE-2012-1342', function () {
			var vector_cve_2012_1342 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2012_1342);
			base.getVector().should.equal(vector_cve_2012_1342);
			base.getScore().should.equal(5.8);
		});

		it('Test Base Metrics : CVE-2013-6014', function () {
			var vector_cve_2013_6014 = "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2013_6014);
			base.getVector().should.equal(vector_cve_2013_6014);
			base.getScore().should.equal(9.3);
		});

		it('Test Base Metrics : CVE-2014-9253', function () {
			var vector_cve_2014_9253 = "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2014_9253);
			base.getVector().should.equal(vector_cve_2014_9253);
			base.getScore().should.equal(5.4);
		});

		it('Test Base Metrics : CVE-2009-0658', function () {
			var vector_cve_2009_0658 = "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2009_0658);
			base.getVector().should.equal(vector_cve_2009_0658);
			base.getScore().should.equal(7.8);
		});

		it('Test Base Metrics : CVE-2011-1265', function () {
			var vector_cve_2011_1265 = "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2011_1265);
			base.getVector().should.equal(vector_cve_2011_1265);
			base.getScore().should.equal(8.8);
		});

		it('Test Base Metrics : CVE-2014-2019', function () {
			var vector_cve_2014_2019 = "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2014_2019);
			base.getVector().should.equal(vector_cve_2014_2019);
			base.getScore().should.equal(4.6);
		});

		it('Test Base Metrics : CVE-2015-0970', function () {
			var vector_cve_2015_0970 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2015_0970);
			base.getVector().should.equal(vector_cve_2015_0970);
			base.getScore().should.equal(8.8);
		});

		it('Test Base Metrics : CVE-2014-0224', function () {
			var vector_cve_2014_0224 = "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2014_0224);
			base.getVector().should.equal(vector_cve_2014_0224);
			base.getScore().should.equal(7.4);
		});

		it('Test Base Metrics : CVE-2012-5376', function () {
			var vector_cve_2012_5376 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2012_5376);
			base.getVector().should.equal(vector_cve_2012_5376);
			base.getScore().should.equal(9.6);
		});

	});

	describe('temporal', function () {

		describe('tempo-e', function () {

			var testSetE = [
				{"value": 'X', "score": 1.00},
				{"value": 'H', "score": 1.00},
				{"value": 'F', "score": 0.97},
				{"value": 'P', "score": 0.94},
				{"value": 'U', "score": 0.91}
			];
			var nameE = 'E';

			it('Test Exploit Code Maturity : '+testSetE[0].value, function () {
				var value = testSetE[0].value;
				var score = testSetE[0].score;
				var tempoE = new CVSS3.TemporalMetrics.E(value);
				tempoE.getName().should.equal(nameE);
				tempoE.getVector().should.equal(nameE+':'+value);
				tempoE.getScore().should.equal(score);
			});

			it('Test Exploit Code Maturity : null', function () {
				var value = testSetE[0].value;
				var score = testSetE[0].score;
				var tempoE = new CVSS3.TemporalMetrics.E(null);
				tempoE.getName().should.equal(nameE);
				tempoE.getVector().should.equal(nameE+':'+value);
				tempoE.getScore().should.equal(score);
			});

			it('Test Exploit Code Maturity : undefined', function () {
				var value = testSetE[0].value;
				var score = testSetE[0].score;
				var tempoE = new CVSS3.TemporalMetrics.E();
				tempoE.getName().should.equal(nameE);
				tempoE.getVector().should.equal(nameE+':'+value);
				tempoE.getScore().should.equal(score);
			});

			it('Test Exploit Code Maturity : '+testSetE[1].value, function () {
				var value = testSetE[1].value;
				var score = testSetE[1].score;
				var tempoE = new CVSS3.TemporalMetrics.E(value);
				tempoE.getName().should.equal(nameE);
				tempoE.getVector().should.equal(nameE+':'+value);
				tempoE.getScore().should.equal(score);
			});

			it('Test Exploit Code Maturity : '+testSetE[2].value, function () {
				var value = testSetE[2].value;
				var score = testSetE[2].score;
				var tempoE = new CVSS3.TemporalMetrics.E(value);
				tempoE.getName().should.equal(nameE);
				tempoE.getVector().should.equal(nameE+':'+value);
				tempoE.getScore().should.equal(score);
			});

			it('Test Exploit Code Maturity : '+testSetE[3].value, function () {
				var value = testSetE[3].value;
				var score = testSetE[3].score;
				var tempoE = new CVSS3.TemporalMetrics.E(value);
				tempoE.getName().should.equal(nameE);
				tempoE.getVector().should.equal(nameE+':'+value);
				tempoE.getScore().should.equal(score);
			});

			it('Test Exploit Code Maturity : '+testSetE[4].value, function () {
				var value = testSetE[4].value;
				var score = testSetE[4].score;
				var tempoE = new CVSS3.TemporalMetrics.E(value);
				tempoE.getName().should.equal(nameE);
				tempoE.getVector().should.equal(nameE+':'+value);
				tempoE.getScore().should.equal(score);
			});

		});

		describe('tempo-rl', function () {

			var testSetRL = [
				{"value": 'X', "score": 1.00},
				{"value": 'U', "score": 1.00},
				{"value": 'W', "score": 0.97},
				{"value": 'T', "score": 0.96},
				{"value": 'O', "score": 0.95}
			];
			var nameRL = 'RL';

			it('Test Remediation Level : '+testSetRL[0].value, function () {
				var value = testSetRL[0].value;
				var score = testSetRL[0].score;
				var tempoRL = new CVSS3.TemporalMetrics.RL(value);
				tempoRL.getName().should.equal(nameRL);
				tempoRL.getVector().should.equal(nameRL+':'+value);
				tempoRL.getScore().should.equal(score);
			});

			it('Test Remediation Level : null', function () {
				var value = testSetRL[0].value;
				var score = testSetRL[0].score;
				var tempoRL = new CVSS3.TemporalMetrics.RL(null);
				tempoRL.getName().should.equal(nameRL);
				tempoRL.getVector().should.equal(nameRL+':'+value);
				tempoRL.getScore().should.equal(score);
			});

			it('Test Remediation Level : undefined', function () {
				var value = testSetRL[0].value;
				var score = testSetRL[0].score;
				var tempoRL = new CVSS3.TemporalMetrics.RL();
				tempoRL.getName().should.equal(nameRL);
				tempoRL.getVector().should.equal(nameRL+':'+value);
				tempoRL.getScore().should.equal(score);
			});

			it('Test Remediation Level : '+testSetRL[1].value, function () {
				var value = testSetRL[1].value;
				var score = testSetRL[1].score;
				var tempoRL = new CVSS3.TemporalMetrics.RL(value);
				tempoRL.getName().should.equal(nameRL);
				tempoRL.getVector().should.equal(nameRL+':'+value);
				tempoRL.getScore().should.equal(score);
			});

			it('Test Remediation Level : '+testSetRL[2].value, function () {
				var value = testSetRL[2].value;
				var score = testSetRL[2].score;
				var tempoRL = new CVSS3.TemporalMetrics.RL(value);
				tempoRL.getName().should.equal(nameRL);
				tempoRL.getVector().should.equal(nameRL+':'+value);
				tempoRL.getScore().should.equal(score);
			});

			it('Test Remediation Level : '+testSetRL[3].value, function () {
				var value = testSetRL[3].value;
				var score = testSetRL[3].score;
				var tempoRL = new CVSS3.TemporalMetrics.RL(value);
				tempoRL.getName().should.equal(nameRL);
				tempoRL.getVector().should.equal(nameRL+':'+value);
				tempoRL.getScore().should.equal(score);
			});

			it('Test Remediation Level : '+testSetRL[4].value, function () {
				var value = testSetRL[4].value;
				var score = testSetRL[4].score;
				var tempoRL = new CVSS3.TemporalMetrics.RL(value);
				tempoRL.getName().should.equal(nameRL);
				tempoRL.getVector().should.equal(nameRL+':'+value);
				tempoRL.getScore().should.equal(score);
			});

		});

		describe('tempo-rc', function () {

			var testSetRC = [
				{"value": 'X', "score": 1.00},
				{"value": 'C', "score": 1.00},
				{"value": 'R', "score": 0.96},
				{"value": 'U', "score": 0.92},
			];
			var nameRC = 'RC';

			it('Test Report Confidence : '+testSetRC[0].value, function () {
				var value = testSetRC[0].value;
				var score = testSetRC[0].score;
				var tempoRL = new CVSS3.TemporalMetrics.RC(value);
				tempoRL.getName().should.equal(nameRC);
				tempoRL.getVector().should.equal(nameRC+':'+value);
				tempoRL.getScore().should.equal(score);
			});

			it('Test Report Confidence : null', function () {
				var value = testSetRC[0].value;
				var score = testSetRC[0].score;
				var tempoRL = new CVSS3.TemporalMetrics.RC(null);
				tempoRL.getName().should.equal(nameRC);
				tempoRL.getVector().should.equal(nameRC+':'+value);
				tempoRL.getScore().should.equal(score);
			});

			it('Test Report Confidence : undefined', function () {
				var value = testSetRC[0].value;
				var score = testSetRC[0].score;
				var tempoRL = new CVSS3.TemporalMetrics.RC();
				tempoRL.getName().should.equal(nameRC);
				tempoRL.getVector().should.equal(nameRC+':'+value);
				tempoRL.getScore().should.equal(score);
			});

			it('Test Report Confidence : '+testSetRC[1].value, function () {
				var value = testSetRC[1].value;
				var score = testSetRC[1].score;
				var tempoRL = new CVSS3.TemporalMetrics.RC(value);
				tempoRL.getName().should.equal(nameRC);
				tempoRL.getVector().should.equal(nameRC+':'+value);
				tempoRL.getScore().should.equal(score);
			});

			it('Test Report Confidence : '+testSetRC[2].value, function () {
				var value = testSetRC[2].value;
				var score = testSetRC[2].score;
				var tempoRL = new CVSS3.TemporalMetrics.RC(value);
				tempoRL.getName().should.equal(nameRC);
				tempoRL.getVector().should.equal(nameRC+':'+value);
				tempoRL.getScore().should.equal(score);
			});

			it('Test Report Confidence : '+testSetRC[3].value, function () {
				var value = testSetRC[3].value;
				var score = testSetRC[3].score;
				var tempoRL = new CVSS3.TemporalMetrics.RC(value);
				tempoRL.getName().should.equal(nameRC);
				tempoRL.getVector().should.equal(nameRC+':'+value);
				tempoRL.getScore().should.equal(score);
			});

		});

		it('Test Temporal Metrics : Input "Exploit Code Maturity" metric', function () {
			var tempo = new CVSS3.TemporalMetrics(new CVSS3.TemporalMetrics.E('U'));
			tempo.e.getVector().should.equal('E:U');
			tempo.e.getScore().should.equal(0.91);
		});

		it('Test Temporal Metrics : Input "Remediation Level" metric', function () {
			var tempo = new CVSS3.TemporalMetrics(new CVSS3.TemporalMetrics.RL('O'));
			tempo.rl.getVector().should.equal('RL:O');
			tempo.rl.getScore().should.equal(0.95);
		});

		it('Test Temporal Metrics : Input "Report Confidence" metric', function () {
			var tempo = new CVSS3.TemporalMetrics(new CVSS3.TemporalMetrics.RC('U'));
			tempo.rc.getVector().should.equal('RC:U');
			tempo.rc.getScore().should.equal(0.92);
		});

		it('Test Temporal Metrics : Input all metric', function () {
			var vector_cve_2013_1937 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2013_1937);
			var tempo = new CVSS3.TemporalMetrics(new CVSS3.TemporalMetrics.E('U')
													,new CVSS3.TemporalMetrics.RL('O')
													,new CVSS3.TemporalMetrics.RC('U'));
			var vector_Lo_score = vector_cve_2013_1937 + "/E:U/RL:O/RC:U";
			tempo.getName().should.equal("TemporalMetrics");
			tempo.getVector(base).should.equal(vector_Lo_score);
			tempo.getScore(base).should.equal(4.9);
		});

		it('Test Temporal Metrics : Undefined', function () {
			var vector_base10 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
			var vector_not_defined = vector_base10 + "/E:X/RL:X/RC:X";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_not_defined);
			base.getVector().should.equal(vector_base10);
			base.getScore().should.equal(10.0);
			var tempo = new CVSS3.TemporalMetrics();
			tempo.getVector(base).should.equal(vector_not_defined);
			tempo.getScore(base).should.equal(10.0);
		});

		it('Test Temporal Metrics : Not Defined', function () {
			var vector_base10_1 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
			var vector_not_defined = vector_base10_1 + "/E:X/RL:X/RC:X";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_not_defined);
			base.getVector().should.equal(vector_base10_1);
			base.getScore().should.equal(10.0);
			var tempo = (new CVSS3.TemporalMetrics()).importVector(vector_not_defined);
			tempo.getVector(base).should.equal(vector_not_defined);
			tempo.getScore(base).should.equal(10.0);
		});

		it('Test Temporal Metrics : Hi Score', function () {
			var vector_base10_2 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
			var vector_hi_score = vector_base10_2 + "/E:H/RL:U/RC:C";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_hi_score);
			base.getVector().should.equal(vector_base10_2);
			base.getScore().should.equal(10.0);
			var tempo = (new CVSS3.TemporalMetrics()).importVector(vector_hi_score);
			tempo.getVector(base).should.equal(vector_hi_score);
			tempo.getScore(base).should.equal(10.0);
		});

		it('Test Temporal Metrics : Lo Score', function () {
			var vector_base10_3 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
			var vector_Lo_score = vector_base10_3 + "/E:U/RL:O/RC:U";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_Lo_score);
			base.getVector().should.equal(vector_base10_3);
			base.getScore().should.equal(10.0);
			var tempo = (new CVSS3.TemporalMetrics()).importVector(vector_Lo_score);
			tempo.getVector(base).should.equal(vector_Lo_score);
			tempo.getScore(base).should.equal(8.0);
		});

		it('Test Temporal Metrics : Zero', function () {
			var vector_base0 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
			var vector_0_score = vector_base0 + "/E:H/RL:U/RC:C";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_0_score);
			base.getVector().should.equal(vector_base0);
			base.getScore().should.equal(0.0);
			var tempo = (new CVSS3.TemporalMetrics()).importVector(vector_0_score);
			tempo.getVector(base).should.equal(vector_0_score);
			tempo.getScore(base).should.equal(0.0);
		});

		it('Test Temporal Metrics : CVE-2013-1937', function () {
			var vector_cve_2013_1937 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2013_1937);
			var vector_hi_score = vector_cve_2013_1937 + "/E:H/RL:U/RC:C";
			var tempoHi = (new CVSS3.TemporalMetrics()).importVector(vector_hi_score);
			tempoHi.getVector(base).should.equal(vector_hi_score);
			tempoHi.getScore(base).should.equal(6.1);
			var vector_Lo_score = vector_cve_2013_1937 + "/E:U/RL:O/RC:U";
			var tempoLo = (new CVSS3.TemporalMetrics()).importVector(vector_Lo_score);
			tempoLo.getVector(base).should.equal(vector_Lo_score);
			tempoLo.getScore(base).should.equal(4.9);
		});
	});

});
