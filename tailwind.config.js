/** @type {import('tailwindcss').Config} */
module.exports = {
  // Scan templates and the external scripts (which build class names) so the
  // JIT compiler emits every utility actually used.
  content: ['./public/**/*.html', './public/js/**/*.js'],
  theme: {
    extend: {},
  },
  plugins: [],
};
