document.addEventListener("DOMContentLoaded", function () {
  const body = document.body;
  const themeOptions = document.querySelectorAll('.theme-option');

  // Apply saved theme
  const savedTheme = localStorage.getItem('theme') || 'light';
  body.classList.add(`theme-${savedTheme}`);

  // Handle theme selection
  themeOptions.forEach(option => {
    option.addEventListener('click', function (e) {
      e.preventDefault();
      const selectedTheme = this.getAttribute('data-theme');

      // Remove all theme classes
      body.classList.remove('theme-light', 'theme-dark', 'theme-pink');

      // Add the new theme class
      body.classList.add(`theme-${selectedTheme}`);

      // Save to localStorage
      localStorage.setItem('theme', selectedTheme);
    });
  });
});
