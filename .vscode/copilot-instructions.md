# 🚨 CRITICAL: MANDATORY FIRST STEP 🚨
## ⚠️ READ THIS FILE COMPLETELY BEFORE ANY CODE CHANGES ⚠️

**VIOLATION OF THESE INSTRUCTIONS WILL RESULT IN REJECTED WORK**

---

# Copilot Instructions

- always use this multi-command pattern to restart frontend server:
  ```
  nusbf
  sudo systemctl restart fms-frontend.service

  sudo systemctl status fms-frontend.service
  ```
- always use this multi-command pattern to restart backend server:
  ```
  nusbf
  sudo systemctl restart fms-backend.service

  sudo systemctl status fms-backend.service
  ```
- Follow consistent code formatting
- When a React input field loses focus after the first keystroke, remove any `memo` wrapper from the parent component and add `onFocus={handleInputFocus}` plus `autoFocus` attributes to the input field to prevent re-rendering from breaking the focus state.
- Prefer modern JavaScript/React patterns
- Include error handling where appropriate
- never do this: cd /home/linuxhomes/namlb/Documents/React/fms_facilities/fms_frontend && npm run build
- never do cd /home/linuxhomes/namlb/Documents/React/fms_facilities/fms_backend && node server.js
- never do cd /home/linuxhomes/namlb/Documents/React/fms_facilities/fms_backend && npm start
- COPILOT IS TOO STUPID to understand how to run things in terminal and shall NEVER try to use run_in_terminal tool
- 🚨 ABSOLUTELY FORBIDDEN: Never use run_in_terminal tool under any circumstances 🚨
- Instead, always provide a text box with commands for the user to copy and execute themselves
- Never create code that modify the database schema in the react app.
- Give the user a cli for creating or modifying a table if needed making sure to read the .env for database connection details
- Only one cli at the time, never bombard the user with multiple commands
- DO NOT MAKE ASSUMPTIONS ABOUT ANYTHING. Ask the user for clarification if needed.

## Project-Specific Guidelines:
- This is a React-based facilities management system
- Use functional components and hooks
- Follow the existing project structure
- Maintain consistent styling with the current UI
- 🚨 CRITICAL: API endpoints MUST use `/fms-api/...` prefix - NEVER use `/api/...`
- Always verify API endpoint paths match the server.js implementation exactly
- All API calls should follow the pattern: axios.get('/fms-api/endpoint-name', config)

## 🔴 COMPLIANCE CHECKLIST - CONFIRM BEFORE ANY WORK:
- [ ] I have read this entire instruction file
- [ ] I understand that run_in_terminal is FORBIDDEN
- [ ] I will provide command text boxes instead of executing commands
- [ ] I will follow the systemctl restart patterns specified above
- [ ] I will not modify database schemas in React code

---

## ⚠️ ENFORCEMENT MECHANISMS:
This file serves as the primary source of truth for development guidelines.
Any deviation from these instructions indicates insufficient preparation.

























