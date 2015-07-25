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

		describe('base-i', function () {

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

		it('Test Base Metrics : CVE-2013-1937', function () {
			var vector_cve_2013_1937 = "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2013_1937);
			base.getVector().should.equal(vector_cve_2013_1937);
			base.getScore().should.equal(6.1);
		});

		it('Test Base Metrics : CVE-2013-0375', function () {
			var vector_cve_2013_0375 = "AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2013_0375);
			base.getVector().should.equal(vector_cve_2013_0375);
			base.getScore().should.equal(6.4);
		});

		it('Test Base Metrics : CVE-2014-3566', function () {
			var vector_cve_2014_3566 = "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2014_3566);
			base.getVector().should.equal(vector_cve_2014_3566);
			base.getScore().should.equal(3.1);
		});

		it('Test Base Metrics : CVE-2012-1516', function () {
			var vector_cve_2012_1516 = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2012_1516);
			base.getVector().should.equal(vector_cve_2012_1516);
			base.getScore().should.equal(9.9);
		});

		it('Test Base Metrics : CVE-2009-0783', function () {
			var vector_cve_2009_0783 = "AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2009_0783);
			base.getVector().should.equal(vector_cve_2009_0783);
			base.getScore().should.equal(4.2);
		});

		it('Test Base Metrics : CVE-2012-0384', function () {
			var vector_cve_2012_0384 = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2012_0384);
			base.getVector().should.equal(vector_cve_2012_0384);
			base.getScore().should.equal(8.8);
		});

		it('Test Base Metrics : CVE-2015-1098', function () {
			var vector_cve_2015_1098 = "AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2015_1098);
			base.getVector().should.equal(vector_cve_2015_1098);
			base.getScore().should.equal(7.8);
		});

		it('Test Base Metrics : CVE-2014-0160', function () {
			var vector_cve_2014_0160 = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2014_0160);
			base.getVector().should.equal(vector_cve_2014_0160);
			base.getScore().should.equal(7.5);
		});

		it('Test Base Metrics : CVE-2014-6271', function () {
			var vector_cve_2014_6271 = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2014_6271);
			base.getVector().should.equal(vector_cve_2014_6271);
			base.getScore().should.equal(9.8);
		});

		it('Test Base Metrics : CVE-2008-1447', function () {
			var vector_cve_2008_1447 = "AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2008_1447);
			base.getVector().should.equal(vector_cve_2008_1447);
			base.getScore().should.equal(6.8);
		});

		it('Test Base Metrics : CVE-2014-2005', function () {
			var vector_cve_2014_2005 = "AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2014_2005);
			base.getVector().should.equal(vector_cve_2014_2005);
			base.getScore().should.equal(6.8);
		});

		it('Test Base Metrics : CVE-2010-0467', function () {
			var vector_cve_2010_0467 = "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2010_0467);
			base.getVector().should.equal(vector_cve_2010_0467);
			base.getScore().should.equal(5.8);
		});

		it('Test Base Metrics : CVE-2012-1342', function () {
			var vector_cve_2012_1342 = "AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2012_1342);
			base.getVector().should.equal(vector_cve_2012_1342);
			base.getScore().should.equal(5.8);
		});

		it('Test Base Metrics : CVE-2013-6014', function () {
			var vector_cve_2013_6014 = "AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2013_6014);
			base.getVector().should.equal(vector_cve_2013_6014);
			base.getScore().should.equal(9.3);
		});

		it('Test Base Metrics : CVE-2014-9253', function () {
			var vector_cve_2014_9253 = "AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2014_9253);
			base.getVector().should.equal(vector_cve_2014_9253);
			base.getScore().should.equal(5.4);
		});

		it('Test Base Metrics : CVE-2009-0658', function () {
			var vector_cve_2009_0658 = "AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2009_0658);
			base.getVector().should.equal(vector_cve_2009_0658);
			base.getScore().should.equal(7.8);
		});

		it('Test Base Metrics : CVE-2011-1265', function () {
			var vector_cve_2011_1265 = "AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2011_1265);
			base.getVector().should.equal(vector_cve_2011_1265);
			base.getScore().should.equal(8.8);
		});

		it('Test Base Metrics : CVE-2014-2019', function () {
			var vector_cve_2014_2019 = "AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2014_2019);
			base.getVector().should.equal(vector_cve_2014_2019);
			base.getScore().should.equal(4.6);
		});

		it('Test Base Metrics : CVE-2015-0970', function () {
			var vector_cve_2015_0970 = "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2015_0970);
			base.getVector().should.equal(vector_cve_2015_0970);
			base.getScore().should.equal(8.8);
		});

		it('Test Base Metrics : CVE-2014-0224', function () {
			var vector_cve_2014_0224 = "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2014_0224);
			base.getVector().should.equal(vector_cve_2014_0224);
			base.getScore().should.equal(7.4);
		});

		it('Test Base Metrics : CVE-2012-5376', function () {
			var vector_cve_2012_5376 = "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H";
			var base = (new CVSS3.BaseMetrics()).importVector(vector_cve_2012_5376);
			base.getVector().should.equal(vector_cve_2012_5376);
			base.getScore().should.equal(9.6);
		});

	});

});
