// WiFi 보안 분석 리포트 생성기
// 사용법: generateWiFiAnalysisReport(measurementData)

class WiFiAnalysisReportGenerator {
    constructor() {
        this.reportData = {};
        this.riskLevels = {
            'critical': { score: 90, color: '#dc3545', label: '매우 위험' },
            'high': { score: 70, color: '#fd7e14', label: '높음' },
            'medium': { score: 50, color: '#ffc107', label: '보통' },
            'low': { score: 30, color: '#28a745', label: '낮음' },
            'minimal': { score: 10, color: '#17a2b8', label: '매우 낮음' }
        };
    }

    // 메인 리포트 생성 함수
    generateReport(measurementData) {
        if (!measurementData || measurementData.length === 0) {
            return this.generateEmptyReport();
        }

        this.analyzeData(measurementData);
        return this.createReportHTML();
    }

    // 데이터 분석
    analyzeData(data) {
        this.reportData = {
            overview: this.calculateOverview(data),
            security: this.analyzeSecurityStatus(data),
            network: this.analyzeNetworkEnvironment(data),
            location: this.analyzeByLocation(data),
            threats: this.identifyThreats(data),
            recommendations: this.generateRecommendations(data),
            technical: this.generateTechnicalAnalysis(data)
        };
    }

    // 전체 개요 분석
    calculateOverview(data) {
        const totalNetworks = data.length;
        const uniqueLocations = [...new Set(data.map(d => d.location))].length;
        const avgSignal = Math.round(data.reduce((sum, d) => sum + d.signal, 0) / totalNetworks);
        const timeRange = this.getTimeRange(data);
        
        return {
            totalNetworks,
            uniqueLocations,
            avgSignal,
            timeRange,
            scanDuration: this.calculateScanDuration(data),
            dataQuality: this.assessDataQuality(data)
        };
    }

    // 보안 상태 분석
    analyzeSecurityStatus(data) {
        const securityTypes = {};
        const openNetworks = [];
        const weakSecurity = [];
        const strongSecurity = [];

        data.forEach(network => {
            // 보안 방식별 카운트
            securityTypes[network.security] = (securityTypes[network.security] || 0) + 1;

            // 보안 수준별 분류
            if (network.security === 'Open') {
                openNetworks.push(network);
            } else if (['WEP', 'WPA'].includes(network.security)) {
                weakSecurity.push(network);
            } else if (['WPA2', 'WPA3'].includes(network.security)) {
                strongSecurity.push(network);
            }
        });

        const securityScore = this.calculateSecurityScore(securityTypes, data.length);

        return {
            securityTypes,
            openNetworks,
            weakSecurity,
            strongSecurity,
            securityScore,
            vulnerabilityLevel: this.getVulnerabilityLevel(securityScore)
        };
    }

    // 네트워크 환경 분석
    analyzeNetworkEnvironment(data) {
        const channels = {};
        const frequencies = { '2.4GHz': 0, '5GHz': 0 };
        const signalDistribution = { strong: 0, medium: 0, weak: 0 };
        const networkDensity = this.calculateNetworkDensity(data);

        data.forEach(network => {
            // 채널 분포
            channels[network.channel] = (channels[network.channel] || 0) + 1;

            // 주파수 분포
            const freq = this.determineFrequency(network.channel);
            frequencies[freq]++;

            // 신호 강도 분포
            if (network.signal > -50) signalDistribution.strong++;
            else if (network.signal > -70) signalDistribution.medium++;
            else signalDistribution.weak++;
        });

        const channelInterference = this.analyzeChannelInterference(channels);
        const congestionLevel = this.calculateCongestionLevel(networkDensity, channelInterference);

        return {
            channels,
            frequencies,
            signalDistribution,
            networkDensity,
            channelInterference,
            congestionLevel
        };
    }

    // 위치별 분석
    analyzeByLocation(data) {
        const locationStats = {};
        
        data.forEach(network => {
            if (!locationStats[network.location]) {
                locationStats[network.location] = {
                    count: 0,
                    avgSignal: 0,
                    openNetworks: 0,
                    strongestSignal: -100,
                    weakestSignal: 0,
                    securityTypes: {},
                    riskScore: 0
                };
            }

            const loc = locationStats[network.location];
            loc.count++;
            loc.avgSignal += network.signal;
            
            if (network.security === 'Open') loc.openNetworks++;
            if (network.signal > loc.strongestSignal) loc.strongestSignal = network.signal;
            if (network.signal < loc.weakestSignal) loc.weakestSignal = network.signal;
            
            loc.securityTypes[network.security] = (loc.securityTypes[network.security] || 0) + 1;
        });

        // 평균 계산 및 위험도 점수 계산
        Object.keys(locationStats).forEach(location => {
            const loc = locationStats[location];
            loc.avgSignal = Math.round(loc.avgSignal / loc.count);
            loc.riskScore = this.calculateLocationRiskScore(loc);
            loc.riskLevel = this.getRiskLevelFromScore(loc.riskScore);
        });

        return locationStats;
    }

    // 위협 요소 식별
    identifyThreats(data) {
        const threats = [];

        // Open 네트워크 위협
        const openNetworks = data.filter(n => n.security === 'Open');
        if (openNetworks.length > 0) {
            threats.push({
                type: 'open_networks',
                severity: 'critical',
                count: openNetworks.length,
                description: '암호화되지 않은 네트워크',
                networks: openNetworks.map(n => n.ssid),
                impact: '데이터 도청, 중간자 공격 위험'
            });
        }

        // 약한 보안 위협
        const weakSecurity = data.filter(n => ['WEP', 'WPA'].includes(n.security));
        if (weakSecurity.length > 0) {
            threats.push({
                type: 'weak_security',
                severity: 'high',
                count: weakSecurity.length,
                description: '취약한 보안 프로토콜',
                networks: weakSecurity.map(n => n.ssid),
                impact: '보안 키 탈취, 무단 접근 위험'
            });
        }

        // 강한 신호 위협 (너무 가까운 거리)
        const strongSignals = data.filter(n => n.signal > -30);
        if (strongSignals.length > 0) {
            threats.push({
                type: 'strong_signals',
                severity: 'medium',
                count: strongSignals.length,
                description: '매우 강한 신호 (근거리)',
                networks: strongSignals.map(n => n.ssid),
                impact: '개인정보 노출, 물리적 접근 가능성'
            });
        }

        // 숨겨진 네트워크
        const hiddenNetworks = data.filter(n => n.ssid.includes('Hidden') || n.ssid.includes('hidden'));
        if (hiddenNetworks.length > 0) {
            threats.push({
                type: 'hidden_networks',
                severity: 'medium',
                count: hiddenNetworks.length,
                description: '숨겨진 네트워크',
                networks: hiddenNetworks.map(n => n.ssid),
                impact: '의심스러운 활동, 보안 우회 시도'
            });
        }

        // IoT 기기 위협
        const iotDevices = data.filter(n => 
            n.ssid.includes('Samsung') || 
            n.ssid.includes('DIRECT-') || 
            n.ssid.includes('Printer') ||
            n.ssid.includes('[floor')
        );
        if (iotDevices.length > 0) {
            threats.push({
                type: 'iot_devices',
                severity: 'medium',
                count: iotDevices.length,
                description: 'IoT 기기 네트워크',
                networks: iotDevices.map(n => n.ssid),
                impact: '기기 탈취, 측면 공격 경로'
            });
        }

        return threats.sort((a, b) => this.getSeverityWeight(b.severity) - this.getSeverityWeight(a.severity));
    }

    // 개선 권고사항 생성
    generateRecommendations(data) {
        const recommendations = [];
        const threats = this.identifyThreats(data);

        // 위협별 권고사항
        threats.forEach(threat => {
            switch(threat.type) {
                case 'open_networks':
                    recommendations.push({
                        priority: 'urgent',
                        category: '보안 강화',
                        title: 'Open 네트워크 즉시 보안 설정',
                        description: `${threat.count}개의 암호화되지 않은 네트워크가 발견되었습니다.`,
                        actions: [
                            'WPA3 또는 WPA2 암호화 즉시 적용',
                            '강력한 비밀번호 설정 (12자리 이상)',
                            '게스트 네트워크 분리 운영 검토',
                            '정기적인 비밀번호 변경 정책 수립'
                        ],
                        impact: '데이터 보안 95% 향상'
                    });
                    break;

                case 'weak_security':
                    recommendations.push({
                        priority: 'high',
                        category: '보안 업그레이드',
                        title: '구형 보안 프로토콜 업데이트',
                        description: `${threat.count}개의 취약한 보안 설정이 발견되었습니다.`,
                        actions: [
                            'WEP/WPA에서 WPA2/WPA3로 업그레이드',
                            '라우터 펌웨어 최신 버전 업데이트',
                            'WPS 기능 비활성화',
                            '802.11w (Management Frame Protection) 활성화'
                        ],
                        impact: '보안 취약점 80% 감소'
                    });
                    break;

                case 'iot_devices':
                    recommendations.push({
                        priority: 'medium',
                        category: 'IoT 보안',
                        title: 'IoT 기기 보안 강화',
                        description: `${threat.count}개의 IoT 기기가 감지되었습니다.`,
                        actions: [
                            'IoT 전용 네트워크 분리 구성',
                            '기기별 접근 권한 제한',
                            '정기적인 펌웨어 업데이트',
                            '불필요한 기기 네트워크 연결 차단'
                        ],
                        impact: 'IoT 보안 위험 70% 감소'
                    });
                    break;
            }
        });

        // 일반적인 권고사항
        const generalRecommendations = this.getGeneralRecommendations(data);
        recommendations.push(...generalRecommendations);

        return recommendations.sort((a, b) => this.getPriorityWeight(b.priority) - this.getPriorityWeight(a.priority));
    }

    // 기술적 분석
    generateTechnicalAnalysis(data) {
        const analysis = {
            channelOptimization: this.analyzeChannelOptimization(data),
            signalCoverage: this.analyzeSignalCoverage(data),
            interferenceAnalysis: this.analyzeInterference(data),
            performanceMetrics: this.calculatePerformanceMetrics(data),
            securityMetrics: this.calculateSecurityMetrics(data)
        };

        return analysis;
    }

    // 유틸리티 함수들
    calculateSecurityScore(securityTypes, total) {
        let score = 100;
        
        const openCount = securityTypes['Open'] || 0;
        const wepCount = securityTypes['WEP'] || 0;
        const wpaCount = securityTypes['WPA'] || 0;
        
        score -= (openCount / total) * 50;  // Open: -50점
        score -= (wepCount / total) * 30;   // WEP: -30점
        score -= (wpaCount / total) * 20;   // WPA: -20점
        
        return Math.max(0, Math.round(score));
    }

    getVulnerabilityLevel(score) {
        if (score >= 90) return 'minimal';
        if (score >= 70) return 'low';
        if (score >= 50) return 'medium';
        if (score >= 30) return 'high';
        return 'critical';
    }

    determineFrequency(channel) {
        if (channel <= 14) return '2.4GHz';
        return '5GHz';
    }

    calculateNetworkDensity(data) {
        const locations = [...new Set(data.map(d => d.location))];
        return {
            totalNetworks: data.length,
            avgPerLocation: Math.round(data.length / locations.length),
            maxPerLocation: Math.max(...locations.map(loc => 
                data.filter(d => d.location === loc).length
            ))
        };
    }

    analyzeChannelInterference(channels) {
        const interference = {};
        const overlappingChannels = {
            1: [1, 2, 3, 4, 5],
            6: [4, 5, 6, 7, 8],
            11: [9, 10, 11, 12, 13]
        };

        Object.keys(overlappingChannels).forEach(mainChannel => {
            let interferenceCount = 0;
            overlappingChannels[mainChannel].forEach(ch => {
                interferenceCount += channels[ch] || 0;
            });
            interference[mainChannel] = interferenceCount;
        });

        return interference;
    }

    calculateLocationRiskScore(locationData) {
        let score = 0;
        
        // Open 네트워크 점수
        score += (locationData.openNetworks / locationData.count) * 40;
        
        // 네트워크 밀도 점수
        if (locationData.count > 15) score += 20;
        else if (locationData.count > 10) score += 10;
        
        // 강한 신호 점수
        if (locationData.strongestSignal > -30) score += 15;
        
        // 약한 보안 점수
        const weakCount = (locationData.securityTypes['WEP'] || 0) + (locationData.securityTypes['WPA'] || 0);
        score += (weakCount / locationData.count) * 25;
        
        return Math.min(100, Math.round(score));
    }

    getRiskLevelFromScore(score) {
        if (score >= 80) return 'critical';
        if (score >= 60) return 'high';
        if (score >= 40) return 'medium';
        if (score >= 20) return 'low';
        return 'minimal';
    }

    getSeverityWeight(severity) {
        const weights = { critical: 4, high: 3, medium: 2, low: 1, minimal: 0 };
        return weights[severity] || 0;
    }

    getPriorityWeight(priority) {
        const weights = { urgent: 4, high: 3, medium: 2, low: 1 };
        return weights[priority] || 0;
    }

    getTimeRange(data) {
        const timestamps = data.map(d => new Date(d.timestamp)).sort();
        const start = timestamps[0];
        const end = timestamps[timestamps.length - 1];
        
        return {
            start: start.toLocaleString('ko-KR'),
            end: end.toLocaleString('ko-KR'),
            duration: this.formatDuration(end - start)
        };
    }

    formatDuration(ms) {
        const hours = Math.floor(ms / (1000 * 60 * 60));
        const minutes = Math.floor((ms % (1000 * 60 * 60)) / (1000 * 60));
        
        if (hours > 0) return `${hours}시간 ${minutes}분`;
        if (minutes > 0) return `${minutes}분`;
        return '1분 미만';
    }

    // HTML 리포트 생성
    createReportHTML() {
        const { overview, security, network, location, threats, recommendations } = this.reportData;

        return `
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi 보안 분석 리포트</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f7fa; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header .subtitle { opacity: 0.9; margin-top: 10px; }
        .section { background: white; margin-bottom: 30px; border-radius: 10px; padding: 25px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section h2 { color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; margin-top: 0; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .metric-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #667eea; }
        .metric-value { font-size: 2em; font-weight: bold; color: #333; }
        .metric-label { color: #666; margin-top: 5px; }
        .risk-critical { background: #dc3545; color: white; }
        .risk-high { background: #fd7e14; color: white; }
        .risk-medium { background: #ffc107; color: black; }
        .risk-low { background: #28a745; color: white; }
        .risk-minimal { background: #17a2b8; color: white; }
        .threat-item { margin-bottom: 15px; padding: 15px; border-left: 4px solid #dc3545; background: #f8f9fa; }
        .recommendation-item { margin-bottom: 20px; padding: 20px; border-left: 4px solid #28a745; background: #f8f9fa; }
        .priority-urgent { border-left-color: #dc3545; }
        .priority-high { border-left-color: #fd7e14; }
        .priority-medium { border-left-color: #ffc107; }
        .chart-container { height: 300px; margin: 20px 0; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
        .security-badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
        .security-open { background: #dc3545; color: white; }
        .security-wep { background: #fd7e14; color: white; }
        .security-wpa { background: #ffc107; color: black; }
        .security-wpa2 { background: #28a745; color: white; }
        .security-wpa3 { background: #17a2b8; color: white; }
        @media print { body { background: white; } .section { box-shadow: none; border: 1px solid #ddd; } }
    </style>
</head>
<body>
    <div class="container">
        ${this.generateHeaderSection()}
        ${this.generateOverviewSection()}
        ${this.generateSecuritySection()}
        ${this.generateThreatSection()}
        ${this.generateLocationSection()}
        ${this.generateRecommendationSection()}
        ${this.generateTechnicalSection()}
        ${this.generateFooterSection()}
    </div>
    
    <script>
        window.onload = function() {
            // 차트 생성 로직 (Chart.js 또는 다른 차트 라이브러리 사용 시)
            console.log('WiFi 보안 분석 리포트가 생성되었습니다.');
        };
        
        function printReport() {
            window.print();
        }
        
        function exportToPDF() {
            // PDF 내보내기 로직 (html2pdf.js 등 사용)
            alert('PDF 내보내기 기능은 추가 라이브러리가 필요합니다.');
        }
    </script>
</body>
</html>`;
    }

    generateHeaderSection() {
        const { overview } = this.reportData;
        return `
        <div class="header">
            <h1>🔒 WiFi 보안 분석 리포트</h1>
            <div class="subtitle">
                생성일시: ${new Date().toLocaleString('ko-KR')} | 
                분석 기간: ${overview.timeRange.duration} | 
                총 ${overview.totalNetworks}개 네트워크 분석
            </div>
        </div>`;
    }

    generateOverviewSection() {
        const { overview, security } = this.reportData;
        return `
        <div class="section">
            <h2>📊 분석 개요</h2>
            <div class="grid">
                <div class="metric-card">
                    <div class="metric-value">${overview.totalNetworks}</div>
                    <div class="metric-label">총 네트워크 수</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${overview.uniqueLocations}</div>
                    <div class="metric-label">측정 위치 수</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${overview.avgSignal} dBm</div>
                    <div class="metric-label">평균 신호 강도</div>
                </div>
                <div class="metric-card risk-${security.vulnerabilityLevel}">
                    <div class="metric-value">${security.securityScore}/100</div>
                    <div class="metric-label">보안 점수</div>
                </div>
            </div>
        </div>`;
    }

    generateSecuritySection() {
        const { security } = this.reportData;
        const securityTypesList = Object.entries(security.securityTypes)
            .map(([type, count]) => `<tr><td><span class="security-badge security-${type.toLowerCase()}">${type}</span></td><td>${count}개</td><td>${Math.round(count/this.reportData.overview.totalNetworks*100)}%</td></tr>`)
            .join('');

        return `
        <div class="section">
            <h2>🛡️ 보안 현황 분석</h2>
            <div class="grid">
                <div>
                    <h3>보안 방식별 분포</h3>
                    <table>
                        <thead>
                            <tr><th>보안 방식</th><th>개수</th><th>비율</th></tr>
                        </thead>
                        <tbody>
                            ${securityTypesList}
                        </tbody>
                    </table>
                </div>
                <div>
                    <h3>보안 위험 요약</h3>
                    <div class="metric-card ${security.openNetworks.length > 0 ? 'risk-critical' : 'risk-low'}">
                        <div class="metric-value">${security.openNetworks.length}</div>
                        <div class="metric-label">오픈 네트워크</div>
                    </div>
                    <div class="metric-card ${security.weakSecurity.length > 0 ? 'risk-high' : 'risk-low'}">
                        <div class="metric-value">${security.weakSecurity.length}</div>
                        <div class="metric-label">취약한 보안</div>
                    </div>
                    <div class="metric-card risk-low">
                        <div class="metric-value">${security.strongSecurity.length}</div>
                        <div class="metric-label">강력한 보안</div>
                    </div>
                </div>
            </div>
        </div>`;
    }

    generateThreatSection() {
        const { threats } = this.reportData;
        const threatsList = threats.map(threat => `
            <div class="threat-item">
                <h4>${threat.description} (${threat.count}개)</h4>
                <p><strong>위험도:</strong> ${this.riskLevels[threat.severity]?.label || threat.severity}</p>
                <p><strong>영향:</strong> ${threat.impact}</p>
                <p><strong>대상 네트워크:</strong> ${threat.networks.slice(0, 5).join(', ')}${threat.networks.length > 5 ? ` 외 ${threat.networks.length - 5}개` : ''}</p>
            </div>
        `).join('');

        return `
        <div class="section">
            <h2>⚠️ 발견된 위협 요소</h2>
            ${threats.length > 0 ? threatsList : '<p>발견된 주요 위협 요소가 없습니다.</p>'}
        </div>`;
    }

    generateLocationSection() {
        const { location } = this.reportData;
        const locationList = Object.entries(location).map(([loc, data]) => `
            <tr>
                <td>${loc}</td>
                <td>${data.count}개</td>
                <td>${data.avgSignal} dBm</td>
                <td>${data.openNetworks}개</td>
                <td><span class="risk-${data.riskLevel}" style="padding: 4px 8px; border-radius: 4px; color: white;">${data.riskScore}/100</span></td>
            </tr>
        `).join('');

        return `
        <div class="section">
            <h2>📍 위치별 분석</h2>
            <table>
                <thead>
                    <tr><th>위치</th><th>네트워크 수</th><th>평균 신호</th><th>오픈 네트워크</th><th>위험도</th></tr>
                </thead>
                <tbody>
                    ${locationList}
                </tbody>
            </table>
        </div>`;
    }

    generateRecommendationSection() {
        const { recommendations } = this.reportData;
        const recommendationsList = recommendations.map(rec => `
            <div class="recommendation-item priority-${rec.priority}">
                <h4>${rec.title}</h4>
                <p>${rec.description}</p>
                <p><strong>우선순위:</strong> ${rec.priority === 'urgent' ? '긴급' : rec.priority === 'high' ? '높음' : '보통'}</p>
                <ul>
                    ${rec.actions.map(action => `<li>${action}</li>`).join('')}
                </ul>
                <p><strong>예상 효과:</strong> ${rec.impact}</p>
            </div>
        `).join('');

        return `
        <div class="section">
            <h2>💡 개선 권고사항</h2>
            ${recommendationsList}
        </div>`;
    }

    generateTechnicalSection() {
        const { network } = this.reportData;
        const channelList = Object.entries(network.channels)
            .sort(([a], [b]) => parseInt(a) - parseInt(b))
            .map(([channel, count]) => `<tr><td>채널 ${channel}</td><td>${count}개</td><td>${this.getChannelInterferenceLevel(channel, network.channelInterference)}</td></tr>`)
            .join('');

        return `
        <div class="section">
            <h2>🔧 기술적 분석</h2>
            <div class="grid">
                <div>
                    <h3>채널 사용 현황</h3>
                    <table>
                        <thead>
                            <tr><th>채널</th><th>사용 수</th><th>간섭 수준</th></tr>
                        </thead>
                        <tbody>
                            ${channelList}
                        </tbody>
                    </table>
                </div>
                <div>
                    <h3>네트워크 환경</h3>
                    <div class="metric-card">
                        <div class="metric-value">${network.frequencies['2.4GHz']}</div>
                        <div class="metric-label">2.4GHz 네트워크</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">${network.frequencies['5GHz']}</div>
                        <div class="metric-label">5GHz 네트워크</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">${network.networkDensity.avgPerLocation}</div>
                        <div class="metric-label">위치당 평균 네트워크</div>
                    </div>
                </div>
            </div>
            
            <h3>신호 강도 분포</h3>
            <div class="grid">
                <div class="metric-card risk-low">
                    <div class="metric-value">${network.signalDistribution.strong}</div>
                    <div class="metric-label">강한 신호 (-50dBm 이상)</div>
                </div>
                <div class="metric-card risk-medium">
                    <div class="metric-value">${network.signalDistribution.medium}</div>
                    <div class="metric-label">보통 신호 (-50~-70dBm)</div>
                </div>
                <div class="metric-card risk-high">
                    <div class="metric-value">${network.signalDistribution.weak}</div>
                    <div class="metric-label">약한 신호 (-70dBm 이하)</div>
                </div>
            </div>
        </div>`;
    }

    generateFooterSection() {
        return `
        <div class="section">
            <h2>📋 리포트 정보</h2>
            <p><strong>생성 도구:</strong> WiFi 보안 분석기 v1.0</p>
            <p><strong>분석 기준:</strong> IEEE 802.11 표준, WPA3 보안 가이드라인</p>
            <p><strong>권고사항 기준:</strong> NIST 사이버보안 프레임워크, OWASP IoT 보안 가이드</p>
            
            <div style="margin-top: 20px; text-align: center;">
                <button onclick="printReport()" style="background: #667eea; color: white; padding: 10px 20px; border: none; border-radius: 5px; margin-right: 10px; cursor: pointer;">📄 인쇄</button>
                <button onclick="exportToPDF()" style="background: #28a745; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">📁 PDF 저장</button>
            </div>
        </div>`;
    }

    // 추가 유틸리티 함수들
    getChannelInterferenceLevel(channel, interferenceData) {
        const channelNum = parseInt(channel);
        let interferenceLevel = '낮음';
        
        // 2.4GHz 대역 간섭 분석
        if (channelNum <= 14) {
            if ([1, 6, 11].includes(channelNum)) {
                const interference = interferenceData[channelNum] || 0;
                if (interference > 5) interferenceLevel = '높음';
                else if (interference > 3) interferenceLevel = '보통';
            } else {
                interferenceLevel = '높음'; // 겹치는 채널
            }
        }
        
        return interferenceLevel;
    }

    calculateScanDuration(data) {
        if (data.length === 0) return '0분';
        
        const timestamps = data.map(d => new Date(d.timestamp));
        const start = Math.min(...timestamps);
        const end = Math.max(...timestamps);
        
        return this.formatDuration(end - start);
    }

    assessDataQuality(data) {
        let qualityScore = 100;
        
        // 데이터 완성도 검사
        const missingSignal = data.filter(d => !d.signal || d.signal === 0).length;
        const missingSecurity = data.filter(d => !d.security).length;
        const missingChannel = data.filter(d => !d.channel).length;
        
        qualityScore -= (missingSignal / data.length) * 30;
        qualityScore -= (missingSecurity / data.length) * 20;
        qualityScore -= (missingChannel / data.length) * 10;
        
        return {
            score: Math.max(0, Math.round(qualityScore)),
            issues: {
                missingSignal,
                missingSecurity,
                missingChannel
            }
        };
    }

    calculateCongestionLevel(networkDensity, channelInterference) {
        let congestionScore = 0;
        
        // 네트워크 밀도 기반 점수
        if (networkDensity.avgPerLocation > 20) congestionScore += 40;
        else if (networkDensity.avgPerLocation > 15) congestionScore += 30;
        else if (networkDensity.avgPerLocation > 10) congestionScore += 20;
        
        // 채널 간섭 기반 점수
        const highInterferenceChannels = Object.values(channelInterference).filter(count => count > 5).length;
        congestionScore += highInterferenceChannels * 15;
        
        if (congestionScore >= 70) return '심각';
        if (congestionScore >= 50) return '높음';
        if (congestionScore >= 30) return '보통';
        return '낮음';
    }

    analyzeChannelOptimization(data) {
        const channelUsage = {};
        data.forEach(network => {
            const freq = this.determineFrequency(network.channel);
            if (!channelUsage[freq]) channelUsage[freq] = {};
            channelUsage[freq][network.channel] = (channelUsage[freq][network.channel] || 0) + 1;
        });

        const recommendations = [];
        
        // 2.4GHz 최적화 권고
        if (channelUsage['2.4GHz']) {
            const channels24 = channelUsage['2.4GHz'];
            const overloadedChannels = Object.entries(channels24).filter(([ch, count]) => count > 3);
            
            if (overloadedChannels.length > 0) {
                recommendations.push({
                    type: '2.4GHz 채널 최적화',
                    description: `채널 ${overloadedChannels.map(([ch]) => ch).join(', ')}에 과부하 발생`,
                    suggestion: '채널 1, 6, 11 사용 권장 (비겹침 채널)'
                });
            }
        }

        return {
            usage: channelUsage,
            recommendations
        };
    }

    analyzeSignalCoverage(data) {
        const signalRanges = {
            excellent: data.filter(d => d.signal > -50).length,
            good: data.filter(d => d.signal > -60 && d.signal <= -50).length,
            fair: data.filter(d => d.signal > -70 && d.signal <= -60).length,
            poor: data.filter(d => d.signal <= -70).length
        };

        const coverage = {
            excellent: Math.round((signalRanges.excellent / data.length) * 100),
            good: Math.round((signalRanges.good / data.length) * 100),
            fair: Math.round((signalRanges.fair / data.length) * 100),
            poor: Math.round((signalRanges.poor / data.length) * 100)
        };

        return { signalRanges, coverage };
    }

    analyzeInterference(data) {
        const channelMap = {};
        
        data.forEach(network => {
            const channel = network.channel;
            if (!channelMap[channel]) channelMap[channel] = [];
            channelMap[channel].push(network);
        });

        const interferenceIssues = [];
        
        // 2.4GHz 간섭 분석
        const overlappingGroups = [
            [1, 2, 3, 4, 5],
            [6, 7, 8, 9, 10],
            [11, 12, 13, 14]
        ];

        overlappingGroups.forEach((group, index) => {
            let totalNetworks = 0;
            group.forEach(ch => {
                totalNetworks += (channelMap[ch] || []).length;
            });
            
            if (totalNetworks > 5) {
                interferenceIssues.push({
                    type: '2.4GHz 간섭',
                    channels: group,
                    networkCount: totalNetworks,
                    severity: totalNetworks > 10 ? 'high' : 'medium'
                });
            }
        });

        return interferenceIssues;
    }

    calculatePerformanceMetrics(data) {
        const metrics = {
            averageSignalStrength: Math.round(data.reduce((sum, d) => sum + d.signal, 0) / data.length),
            signalVariance: this.calculateVariance(data.map(d => d.signal)),
            channelDistribution: this.calculateChannelDistribution(data),
            frequencyBalance: this.calculateFrequencyBalance(data)
        };

        return metrics;
    }

    calculateSecurityMetrics(data) {
        const total = data.length;
        const metrics = {
            securityCompliance: Math.round((data.filter(d => ['WPA2', 'WPA3'].includes(d.security)).length / total) * 100),
            encryptionCoverage: Math.round((data.filter(d => d.security !== 'Open').length / total) * 100),
            modernSecurity: Math.round((data.filter(d => d.security === 'WPA3').length / total) * 100),
            riskExposure: Math.round((data.filter(d => ['Open', 'WEP'].includes(d.security)).length / total) * 100)
        };

        return metrics;
    }

    calculateVariance(values) {
        const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
        const squaredDiffs = values.map(val => Math.pow(val - mean, 2));
        return Math.round(squaredDiffs.reduce((sum, diff) => sum + diff, 0) / values.length);
    }

    calculateChannelDistribution(data) {
        const distribution = {};
        data.forEach(network => {
            distribution[network.channel] = (distribution[network.channel] || 0) + 1;
        });
        return distribution;
    }

    calculateFrequencyBalance(data) {
        const freq24 = data.filter(d => this.determineFrequency(d.channel) === '2.4GHz').length;
        const freq5 = data.filter(d => this.determineFrequency(d.channel) === '5GHz').length;
        
        return {
            '2.4GHz': Math.round((freq24 / data.length) * 100),
            '5GHz': Math.round((freq5 / data.length) * 100)
        };
    }

    getGeneralRecommendations(data) {
        const general = [];
        
        // 네트워크 밀도에 따른 권고
        const avgDensity = data.length / [...new Set(data.map(d => d.location))].length;
        if (avgDensity > 15) {
            general.push({
                priority: 'medium',
                category: '성능 최적화',
                title: '네트워크 밀도 관리',
                description: '높은 네트워크 밀도로 인한 성능 저하가 예상됩니다.',
                actions: [
                    '불필요한 네트워크 제거',
                    '5GHz 대역 사용 확대',
                    '액세스 포인트 배치 최적화',
                    '채널 자동 선택 기능 활성화'
                ],
                impact: '네트워크 성능 30% 향상'
            });
        }

        // 보안 정책 권고
        general.push({
            priority: 'medium',
            category: '보안 정책',
            title: '정기 보안 점검 체계 구축',
            description: '지속적인 보안 관리를 위한 체계적 접근이 필요합니다.',
            actions: [
                '월간 네트워크 보안 스캔',
                '분기별 보안 정책 리뷰',
                '연간 보안 인프라 업그레이드',
                '보안 교육 프로그램 운영'
            ],
            impact: '장기적 보안 위험 최소화'
        });

        return general;
    }

    generateEmptyReport() {
        return `
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <meta charset="UTF-8">
            <title>WiFi 보안 분석 리포트</title>
            <style>
                body { font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; text-align: center; }
                .container { max-width: 600px; margin: 0 auto; padding: 50px; }
                .icon { font-size: 4em; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">📊</div>
                <h1>분석할 데이터가 없습니다</h1>
                <p>WiFi 스캔을 실시한 후 리포트를 생성해주세요.</p>
                <button onclick="window.close()" style="background: #667eea; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">닫기</button>
            </div>
        </body>
        </html>`;
    }
}

// 메인 함수: 리포트 생성 및 새 창에서 표시
function generateWiFiAnalysisReport(measurementData) {
    const generator = new WiFiAnalysisReportGenerator();
    const reportHTML = generator.generateReport(measurementData);
    
    // 새 창에서 리포트 열기
    const reportWindow = window.open('', '_blank', 'width=1200,height=800,scrollbars=yes');
    
    if (reportWindow) {
        reportWindow.document.write(reportHTML);
        reportWindow.document.close();
        
        // 리포트 창에 추가 기능 제공
        reportWindow.focus();
        
        // 콘솔에 리포트 데이터도 출력 (디버깅용)
        console.log('WiFi 분석 리포트가 생성되었습니다:', generator.reportData);
        
        return {
            success: true,
            window: reportWindow,
            data: generator.reportData
        };
    } else {
        alert('팝업이 차단되었습니다. 팝업 차단을 해제하고 다시 시도해주세요.');
        return {
            success: false,
            error: 'popup_blocked'
        };
    }
}

// 사용 예시:
// const result = generateWiFiAnalysisReport(measurementData);
// if (result.success) {
//     console.log('리포트가 성공적으로 생성되었습니다.');
// }>