document.addEventListener('DOMContentLoaded', function () {
	const card = document.getElementById('auth-card');
	if (card) {
		requestAnimationFrame(() => card.classList.add('animate-in'));
	}
});
