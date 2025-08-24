document.addEventListener('DOMContentLoaded', () => {
    const signupForm = document.getElementById('signupForm');

    signupForm.addEventListener('submit', function(event) {
        let isValid = true;

        // Reset all validation states
        const formControls = signupForm.querySelectorAll('.form-control, .form-select');
        formControls.forEach(control => {
            control.classList.remove('is-invalid', 'is-valid');
        });

        // Username validation
        const usernameInput = document.getElementById('signupUsername');
        if (usernameInput.value.trim().length < 3) {
            usernameInput.classList.add('is-invalid');
            isValid = false;
        } else {
            usernameInput.classList.add('is-valid');
        }

        // Email validation
        const emailInput = document.getElementById('signupEmail');
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(emailInput.value.trim())) {
            emailInput.classList.add('is-invalid');
            isValid = false;
        } else {
            emailInput.classList.add('is-valid');
        }

        // Password validation
        const passwordInput = document.getElementById('signupPassword');
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(passwordInput.value)) {
            passwordInput.classList.add('is-invalid');
            isValid = false;
        } else {
            passwordInput.classList.add('is-valid');
        }

        // Role validation
        const roleSelect = document.getElementById('signupRole');
        if (roleSelect.value === "") {
            roleSelect.classList.add('is-invalid');
            isValid = false;
        } else {
            roleSelect.classList.add('is-valid');
        }

        if (!isValid) {
            event.preventDefault();
            event.stopPropagation();
        }
    });
});