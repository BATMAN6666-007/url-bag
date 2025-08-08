async function checkUrl() {
            const url = document.getElementById('urlInput').value;
            const resultDiv = document.getElementById('result');
            
            if (!url) {
                resultDiv.innerHTML = '<div class="result">Please enter a URL</div>';
                return;
            }
            
            resultDiv.innerHTML = '<div class="result">Checking...</div>';
            
            try {
                const response = await fetch('/api/check', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                });
                
                const data = await response.json();
                
                if (data.error) {
                    resultDiv.innerHTML = `<div class="result dangerous">Error: ${data.error}</div>`;
                    return;
                }
                
                let cssClass = 'safe';
                if (data.safety_score < 70) cssClass = 'caution';
                if (data.safety_score < 50) cssClass = 'dangerous';
                
                let threatsHtml = '';
                if (data.threats_found && data.threats_found.length > 0) {
                    threatsHtml = '<h4>Threats Found:</h4><ul>';
                    data.threats_found.forEach(threat => {
                        threatsHtml += `<li>${threat}</li>`;
                    });
                    threatsHtml += '</ul>';
                }
                
                resultDiv.innerHTML = `
                    <div class="result ${cssClass}">
                        <h3>Safety Check Results</h3>
                        <p><strong>URL:</strong> ${data.url}</p>
                        <p><strong>Safety Score:</strong> ${data.safety_score}/100</p>
                        <p><strong>Safety Rating:</strong> ${data.safety_rating}</p>
                        ${threatsHtml}
                    </div>
                `;
            } catch (error) {
                resultDiv.innerHTML = `<div class="result dangerous">Error: ${error.message}</div>`;
            }
        }
        
        document.getElementById('urlInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                checkUrl();
            }
        });