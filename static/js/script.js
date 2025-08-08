// Custom JavaScript for Job Portal

document.addEventListener('DOMContentLoaded', function() {
    // Enable tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Confirm before deleting job
    const deleteButtons = document.querySelectorAll('.btn-delete-job');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to delete this job? All applications will also be deleted.')) {
                e.preventDefault();
            }
        });
    });
    
    // Search form enhancement
    const searchForm = document.querySelector('#searchForm');
    if (searchForm) {
        searchForm.addEventListener('submit', function(e) {
            const query = document.querySelector('#searchQuery').value.trim();
            if (!query) {
                e.preventDefault();
                alert('Please enter a search term');
            }
        });
    }
});