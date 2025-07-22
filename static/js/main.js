// Simple form validation
document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const password = form.querySelector('input[name="password"]');
            const newPassword = form.querySelector('input[name="new_password"]');
            
            if (password && password.value.length < 6) {
                e.preventDefault();
                alert('Password must be at least 6 characters long');
                return;
            }
            
            if (newPassword && newPassword.value.length < 6) {
                e.preventDefault();
                alert('Password must be at least 6 characters long');
                return;
            }
        });
    });

    // Delete account button handler
    const deleteBtn = document.getElementById('delete-account-btn');
    if (deleteBtn) {
        deleteBtn.addEventListener('click', function() {
            if (confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
                document.getElementById('delete-account-form').submit();
            }
        });
    }
});