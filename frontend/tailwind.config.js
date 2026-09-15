/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#0a0d14',
          card: '#101522',
          border: '#1b2438',
          accent: '#00f0ff',
          green: '#00ff88',
          red: '#ff0055',
          yellow: '#ffbb00',
          purple: '#9d00ff',
        },
      },
    },
  },
  plugins: [],
};

