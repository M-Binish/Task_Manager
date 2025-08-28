// Main application logic
class TaskManager {
    constructor() {
        this.token = localStorage.getItem('authToken');
        this.currentUser = null;
        this.tasks = [];
        this.currentPage = 0;
        this.pageSize = 10;
        this.filters = {
            search: '',
            status: '',
            priority: ''
        };
        
        this.init();
    }

    async init() {
        this.setupEventListeners();
        this.setupKeyboardShortcuts();
        
        // Hide loading screen after initialization
        setTimeout(() => {
            document.getElementById('loading-screen').style.display = 'none';
        }, 1000);
        
        if (this.token) {
            await this.validateToken();
        } else {
            this.showAuthSection();
        }
    }

    setupEventListeners() {
        // Auth form handlers
        document.getElementById('login-form').addEventListener('submit', (e) => this.handleLogin(e));
        document.getElementById('register-form').addEventListener('submit', (e) => this.handleRegister(e));
        document.getElementById('show-register').addEventListener('click', () => this.showRegisterForm());
        document.getElementById('show-login').addEventListener('click', () => this.showLoginForm());
        document.getElementById('logout-btn').addEventListener('click', () => this.handleLogout());

        // Task management handlers
        document.getElementById('create-task-form').addEventListener('submit', (e) => this.handleCreateTask(e));
        document.getElementById('edit-task-form').addEventListener('submit', (e) => this.handleEditTask(e));
        
        // Search and filter handlers
        document.getElementById('search-input').addEventListener('input', debounce((e) => this.handleSearch(e), 300));
        document.getElementById('status-filter').addEventListener('change', (e) => this.handleFilterChange(e));
        document.getElementById('priority-filter').addEventListener('change', (e) => this.handleFilterChange(e));
        
        // Pagination handlers
        document.getElementById('prev-page').addEventListener('click', () => this.handlePrevPage());
        document.getElementById('next-page').addEventListener('click', () => this.handleNextPage());
        
        // Modal handlers
        document.getElementById('close-modal').addEventListener('click', () => this.closeEditModal());
        document.getElementById('cancel-edit').addEventListener('click', () => this.closeEditModal());
        document.getElementById('close-shortcuts').addEventListener('click', () => this.closeShortcutsModal());
        
        // Click outside modal to close
        document.getElementById('edit-modal').addEventListener('click', (e) => {
            if (e.target.id === 'edit-modal') this.closeEditModal();
        });
        document.getElementById('shortcuts-modal').addEventListener('click', (e) => {
            if (e.target.id === 'shortcuts-modal') this.closeShortcutsModal();
        });
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl + N: New task
            if (e.ctrlKey && e.key === 'n') {
                e.preventDefault();
                document.querySelector('#create-task-form input[name="title"]').focus();
            }
            
            // Ctrl + F: Search
            if (e.ctrlKey && e.key === 'f') {
                e.preventDefault();
                document.getElementById('search-input').focus();
            }
            
            // Ctrl + ?: Help
            if (e.ctrlKey && e.key === '?') {
                e.preventDefault();
                this.showShortcutsModal();
            }
            
            // Escape: Close modals
            if (e.key === 'Escape') {
                this.closeEditModal();
                this.closeShortcutsModal();
            }
        });
    }

    // Authentication methods
    async handleLogin(e) {
        e.preventDefault();
        const formData = new FormData(e.target);
        
        try {
            const response = await this.api('/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams(formData)
            });
            
            if (response.access_token) {
                this.token = response.access_token;
                localStorage.setItem('authToken', this.token);
                toastManager.success('Welcome back! Logged in successfully.');
                await this.showDashboard();
            }
        } catch (error) {
            toastManager.error('Login failed: ' + error.message);
            animationManager.shake(e.target);
        }
    }

    async handleRegister(e) {
        e.preventDefault();
        const formData = new FormData(e.target);
        
        try {
            await this.api('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.fromEntries(formData))
            });
            
            toastManager.success('Account created successfully! Please log in.');
            this.showLoginForm();
        } catch (error) {
            toastManager.error('Registration failed: ' + error.message);
            animationManager.shake(e.target);
        }
    }

    handleLogout() {
        this.token = null;
        this.currentUser = null;
        localStorage.removeItem('authToken');
        toastManager.info('Logged out successfully.');
        this.showAuthSection();
    }

    async validateToken() {
        try {
            await this.loadTasks();
            await this.showDashboard();
        } catch (error) {
            console.error('Token validation failed:', error);
            this.handleLogout();
        }
    }

    // UI Navigation methods
    showAuthSection() {
        pageTransitions.switchPage(
            document.getElementById('dashboard-section'),
            document.getElementById('auth-section')
        );
        document.getElementById('user-info').classList.add('hidden');
    }

    async showDashboard() {
        await pageTransitions.switchPage(
            document.getElementById('auth-section'),
            document.getElementById('dashboard-section')
        );
        
        document.getElementById('user-info').classList.remove('hidden');
        await this.loadStats();
        await this.loadTasks();
    }

    showLoginForm() {
        const loginSection = document.getElementById('login-section');
        const registerSection = document.getElementById('register-section');
        
        pageTransitions.switchPage(registerSection, loginSection);
    }

    showRegisterForm() {
        const loginSection = document.getElementById('login-section');
        const registerSection = document.getElementById('register-section');
        
        pageTransitions.switchPage(loginSection, registerSection);
    }

    // Task management methods
    async handleCreateTask(e) {
        e.preventDefault();
        const formData = new FormData(e.target);
        const taskData = Object.fromEntries(formData);
        
        try {
            const newTask = await this.api('/tasks/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(taskData)
            });
            
            toastManager.success('Task created successfully!');
            e.target.reset();
            await this.loadTasks();
            await this.loadStats();
        } catch (error) {
            toastManager.error('Failed to create task: ' + error.message);
        }
    }

    async handleEditTask(e) {
        e.preventDefault();
        const taskId = document.getElementById('edit-task-id').value;
        const formData = new FormData(e.target);
        const taskData = Object.fromEntries(formData);
        
        // Remove the hidden task ID from the data
        delete taskData.task_id;
        
        try {
            await this.api(`/tasks/${taskId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(taskData)
            });
            
            toastManager.success('Task updated successfully!');
            this.closeEditModal();
            await this.loadTasks();
            await this.loadStats();
        } catch (error) {
            toastManager.error('Failed to update task: ' + error.message);
        }
    }

    async handleDeleteTask(taskId) {
        if (!confirm('Are you sure you want to delete this task?')) return;
        
        try {
            await this.api(`/tasks/${taskId}`, { method: 'DELETE' });
            toastManager.success('Task deleted successfully!');
            await this.loadTasks();
            await this.loadStats();
        } catch (error) {
            toastManager.error('Failed to delete task: ' + error.message);
        }
    }

    async toggleTaskStatus(taskId, currentStatus) {
        const statusMap = {
            'pending': 'in-progress',
            'in-progress': 'completed',
            'completed': 'pending'
        };
        
        const newStatus = statusMap[currentStatus];
        const completed = newStatus === 'completed';
        
        try {
            await this.api(`/tasks/${taskId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus, completed })
            });
            
            toastManager.success(`Task marked as ${newStatus.replace('-', ' ')}!`);
            await this.loadTasks();
            await this.loadStats();
        } catch (error) {
            toastManager.error('Failed to update task status: ' + error.message);
        }
    }

    // Data loading methods
    async loadTasks() {
        this.showTasksLoading();
        
        try {
            const params = new URLSearchParams({
                skip: this.currentPage * this.pageSize,
                limit: this.pageSize,
                ...this.filters
            });
            
            // Remove empty filters
            Object.keys(this.filters).forEach(key => {
                if (!this.filters[key]) params.delete(key);
            });
            
            this.tasks = await this.api(`/tasks/?${params}`);
            this.renderTasks();
        } catch (error) {
            toastManager.error('Failed to load tasks: ' + error.message);
            this.showTasksEmpty();
        }
    }

    async loadStats() {
        try {
            const stats = await this.api('/tasks/stats/summary');
            this.renderStats(stats);
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }

    // Rendering methods
    renderTasks() {
        const container = document.getElementById('tasks-list');
        const emptyState = document.getElementById('tasks-empty');
        const loadingState = document.getElementById('tasks-loading');
        
        loadingState.classList.add('hidden');
        
        if (!this.tasks || this.tasks.length === 0) {
            container.innerHTML = '';
            emptyState.classList.remove('hidden');
            return;
        }
        
        emptyState.classList.add('hidden');
        
        const tasksHTML = this.tasks.map(task => this.createTaskHTML(task)).join('');
        container.innerHTML = tasksHTML;
        
        // Animate task items in
        const taskItems = container.querySelectorAll('.task-item');
        animationManager.staggerIn(taskItems, 100);
        
        this.updatePagination();
    }

    createTaskHTML(task) {
        const createdDate = new Date(task.created_at).toLocaleDateString();
        const updatedDate = new Date(task.updated_at).toLocaleDateString();
        
        return `
            <div class="task-item" data-task-id="${task.id}">
                <div class="task-title">${this.escapeHtml(task.title)}</div>
                <div class="task-description">${this.escapeHtml(task.description)}</div>
                <div class="task-meta">
                    <div class="flex gap-2">
                        <span class="status-badge status-${task.status}">${task.status.replace('-', ' ')}</span>
                        <span class="priority-badge priority-${task.priority}">${task.priority}</span>
                    </div>
                    <div class="task-actions">
                        <button onclick="taskManager.toggleTaskStatus(${task.id}, '${task.status}')" 
                                class="btn-success" title="Toggle Status">
                            <i class="fas fa-check"></i>
                        </button>
                        <button onclick="taskManager.openEditModal(${task.id})" 
                                class="btn-secondary" title="Edit Task">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button onclick="taskManager.handleDeleteTask(${task.id})" 
                                class="btn-danger" title="Delete Task">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
                <div class="text-xs text-gray-500 mt-2">
                    Created: ${createdDate} | Updated: ${updatedDate}
                </div>
            </div>
        `;
    }

    renderStats(stats) {
        document.getElementById('total-tasks').textContent = stats.total;
        document.getElementById('pending-tasks').textContent = stats.pending;
        document.getElementById('progress-tasks').textContent = stats.in_progress;
        document.getElementById('completed-tasks').textContent = stats.completed;
        
        // Animate stat cards
        const statCards = document.querySelectorAll('.stat-card');
        animationManager.staggerIn(statCards, 150);
    }

    showTasksLoading() {
        document.getElementById('tasks-loading').classList.remove('hidden');
        document.getElementById('tasks-empty').classList.add('hidden');
        
        // Show skeleton animation
        animationManager.showSkeleton(document.getElementById('tasks-list'), 3);
    }

    showTasksEmpty() {
        document.getElementById('tasks-loading').classList.add('hidden');
        document.getElementById('tasks-empty').classList.remove('hidden');
        document.getElementById('tasks-list').innerHTML = '';
    }

    updatePagination() {
        const pageInfo = document.getElementById('page-info');
        const prevBtn = document.getElementById('prev-page');
        const nextBtn = document.getElementById('next-page');
        
        const start = this.currentPage * this.pageSize + 1;
        const end = start + this.tasks.length - 1;
        
        pageInfo.textContent = `Showing ${start}-${end}`;
        
        prevBtn.disabled = this.currentPage === 0;
        nextBtn.disabled = this.tasks.length < this.pageSize;
    }

    // Filter and search methods
    handleSearch(e) {
        this.filters.search = e.target.value;
        this.currentPage = 0;
        this.loadTasks();
    }

    handleFilterChange(e) {
        const filterName = e.target.id.replace('-filter', '');
        this.filters[filterName] = e.target.value;
        this.currentPage = 0;
        this.loadTasks();
    }

    handlePrevPage() {
        if (this.currentPage > 0) {
            this.currentPage--;
            this.loadTasks();
        }
    }

    handleNextPage() {
        if (this.tasks.length === this.pageSize) {
            this.currentPage++;
            this.loadTasks();
        }
    }

    // Modal methods
    async openEditModal(taskId) {
        try {
            const task = await this.api(`/tasks/${taskId}`);
            
            document.getElementById('edit-task-id').value = task.id;
            document.getElementById('edit-title').value = task.title;
            document.getElementById('edit-description').value = task.description;
            document.getElementById('edit-status').value = task.status;
            document.getElementById('edit-priority').value = task.priority;
            
            document.getElementById('edit-modal').classList.remove('hidden');
            document.getElementById('edit-modal').classList.add('flex');
            
            // Focus on title field
            setTimeout(() => {
                document.getElementById('edit-title').focus();
            }, 100);
            
        } catch (error) {
            toastManager.error('Failed to load task details: ' + error.message);
        }
    }

    closeEditModal() {
        document.getElementById('edit-modal').classList.add('hidden');
        document.getElementById('edit-modal').classList.remove('flex');
    }

    showShortcutsModal() {
        document.getElementById('shortcuts-modal').classList.remove('hidden');
        document.getElementById('shortcuts-modal').classList.add('flex');
    }

    closeShortcutsModal() {
        document.getElementById('shortcuts-modal').classList.add('hidden');
        document.getElementById('shortcuts-modal').classList.remove('flex');
    }

    // Utility methods
    async api(endpoint, options = {}) {
        const url = `${window.location.origin}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };
        
        if (this.token) {
            config.headers.Authorization = `Bearer ${this.token}`;
        }
        
        const response = await fetch(url, config);
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
            throw new Error(errorData.detail || `HTTP ${response.status}`);
        }
        
        return response.json().catch(() => ({}));
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Utility function for debouncing
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Auto-save functionality for forms
class AutoSave {
    constructor(formSelector, saveInterval = 30000) {
        this.form = document.querySelector(formSelector);
        this.saveInterval = saveInterval;
        this.lastSaved = null;
        this.init();
    }

    init() {
        if (!this.form) return;
        
        this.form.addEventListener('input', () => {
            this.scheduleAutoSave();
        });
        
        // Save on page unload
        window.addEventListener('beforeunload', () => {
            this.saveToLocalStorage();
        });
        
        // Restore on page load
        this.restoreFromLocalStorage();
    }

    scheduleAutoSave() {
        clearTimeout(this.autoSaveTimeout);
        this.autoSaveTimeout = setTimeout(() => {
            this.saveToLocalStorage();
        }, this.saveInterval);
    }

    saveToLocalStorage() {
        const formData = new FormData(this.form);
        const data = Object.fromEntries(formData);
        localStorage.setItem(`autosave_${this.form.id}`, JSON.stringify(data));
        this.lastSaved = Date.now();
    }

    restoreFromLocalStorage() {
        const saved = localStorage.getItem(`autosave_${this.form.id}`);
        if (saved) {
            try {
                const data = JSON.parse(saved);
                Object.entries(data).forEach(([key, value]) => {
                    const input = this.form.querySelector(`[name="${key}"]`);
                    if (input) input.value = value;
                });
                
                if (Object.keys(data).some(key => data[key])) {
                    toastManager.info('Previous form data restored from auto-save.');
                }
            } catch (error) {
                console.error('Failed to restore auto-saved data:', error);
            }
        }
    }

    clearAutoSave() {
        localStorage.removeItem(`autosave_${this.form.id}`);
        clearTimeout(this.autoSaveTimeout);
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    window.taskManager = new TaskManager();
    
    // Initialize auto-save for forms
    window.createTaskAutoSave = new AutoSave('#create-task-form');
});

// Service Worker for offline functionality (optional)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js')
            .then(registration => console.log('SW registered:', registration))
            .catch(error => console.log('SW registration failed:', error));
    });
}
