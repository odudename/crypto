/**
 * JavaScript for the Crypto settings page.
 */
document.addEventListener('DOMContentLoaded', function() {
	var providerRadios = document.querySelectorAll('input[name="crypto_api_provider"]');
	var apiKeyInput = document.getElementById('crypto_api_key');
	
	if (!apiKeyInput) {
		return;
	}
	
	var apiKeyRow = apiKeyInput.closest('tr');
	if (!apiKeyRow) {
		return;
	}

	function toggleApiKeyRow() {
		var selectedProvider = document.querySelector('input[name="crypto_api_provider"]:checked');
		if (selectedProvider && selectedProvider.value === 'coinmarketcap') {
			apiKeyRow.style.display = '';
			// Force layout reflow before setting opacity for transition
			apiKeyRow.offsetHeight;
			apiKeyRow.style.opacity = '1';
		} else {
			apiKeyRow.style.opacity = '0';
			apiKeyRow.style.display = 'none';
		}
	}

	// Initialize state on page load
	toggleApiKeyRow();

	// Attach change event listener to each radio button
	providerRadios.forEach(function(radio) {
		radio.addEventListener('change', toggleApiKeyRow);
	});
});
