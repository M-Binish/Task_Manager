// Animation utilities and effects
class AnimationManager {
    constructor() {
        this.observers = new Map();
        this.initializeObservers();
    }

    // Initialize intersection observers for scroll animations
    initializeObservers() {
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        this.scrollObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-fade-in');
                }
            });
        }, observerOptions);
    }

    // Animate element entrance
    animateIn(element, animationType = 'slide-up', delay = 0) {
        return new Promise((resolve) => {
            setTimeout(() => {
                element.style.opacity = '0';
                element.style.transform = this.getInitialTransform(animationType);
                element.style.transition = 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)';
                
                // Force reflow
                element.offsetHeight;
                
                element.style.opacity = '1';
                element.style.transform = 'translateY(0) scale(1)';
                
                setTimeout(resolve, 500);
            }, delay);
        });
    }

    // Animate element exit
    animateOut(element, animationType = 'slide-up') {
        return new Promise((resolve) => {
            element.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
            element.style.opacity = '0';
            element.style.transform = this.getExitTransform(animationType);
            
            setTimeout(() => {
                element.style.display = 'none';
                resolve();
            }, 300);
        });
    }

    // Get initial transform based on animation type
    getInitialTransform(type) {
        const transforms = {
            'slide-up': 'translateY(20px)',
            'slide-down': 'translateY(-20px)',
            'slide-left': 'translateX(20px)',
            'slide-right': 'translateX(-20px)',
            'scale': 'scale(0.8)',
            'fade': 'translateY(0)'
        };
        return transforms[type] || transforms['slide-up'];
    }

    // Get exit transform based on animation type
    getExitTransform(type) {
        const transforms = {
            'slide-up': 'translateY(-20px)',
            'slide-down': 'translateY(20px)',
            'slide-left': 'translateX(-20px)',
            'slide-right': 'translateX(20px)',
            'scale': 'scale(0.8)',
            'fade': 'translateY(0)'
        };
        return transforms[type] || transforms['slide-up'];
    }

    // Stagger animation for multiple elements
    staggerIn(elements, delay = 100, animationType = 'slide-up') {
        return Promise.all(
            Array.from(elements).map((element, index) => 
                this.animateIn(element, animationType, index * delay)
            )
        );
    }

    // Bounce animation for buttons
    bounceButton(button) {
        button.style.transform = 'scale(0.95)';
        button.style.transition = 'transform 0.1s ease';
        
        setTimeout(() => {
            button.style.transform = 'scale(1)';
        }, 100);
    }

    // Shake animation for errors
    shake(element) {
        element.style.animation = 'shake 0.5s ease-in-out';
        
        setTimeout(() => {
            element.style.animation = '';
        }, 500);
    }

    // Pulse animation for loading states
    pulse(element, duration = 2000) {
        element.classList.add('animate-pulse-soft');
        
        setTimeout(() => {
            element.classList.remove('animate-pulse-soft');
        }, duration);
    }

    // Smooth height transition
    slideToggle(element) {
        if (element.style.maxHeight && element.style.maxHeight !== '0px') {
            // Slide up
            element.style.maxHeight = '0px';
            element.style.paddingTop = '0px';
            element.style.paddingBottom = '0px';
            element.style.marginTop = '0px';
            element.style.marginBottom = '0px';
            element.style.overflow = 'hidden';
            element.style.transition = 'all 0.3s ease';
        } else {
            // Slide down
            element.style.maxHeight = element.scrollHeight + 'px';
            element.style.overflow = 'hidden';
            element.style.transition = 'all 0.3s ease';
            
            setTimeout(() => {
                element.style.maxHeight = 'none';
                element.style.overflow = 'visible';
            }, 300);
        }
    }

    // Ripple effect for buttons
    createRipple(event, element) {
        const ripple = document.createElement('span');
        const rect = element.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = event.clientX - rect.left - size / 2;
        const y = event.clientY - rect.top - size / 2;
        
        ripple.style.cssText = `
            position: absolute;
            border-radius: 50%;
            transform: scale(0);
            animation: ripple 0.6s linear;
            background-color: rgba(255, 255, 255, 0.3);
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            pointer-events: none;
        `;
        
        element.style.position = 'relative';
        element.style.overflow = 'hidden';
        element.appendChild(ripple);
        
        setTimeout(() => {
            ripple.remove();
        }, 600);
    }

    // Loading skeleton animation
    showSkeleton(container, count = 3) {
        const skeletonHTML = Array.from({ length: count }, () => `
            <div class="animate-pulse">
                <div class="bg-gray-200 rounded-lg p-4 mb-3">
                    <div class="h-4 bg-gray-300 rounded w-3/4 mb-2"></div>
                    <div class="h-3 bg-gray-300 rounded w-1/2 mb-2"></div>
                    <div class="h-3 bg-gray-300 rounded w-1/4"></div>
                </div>
            </div>
        `).join('');
        
        container.innerHTML = skeletonHTML;
    }

    // Remove loading skeleton
    hideSkeleton(container) {
        const skeletons = container.querySelectorAll('.animate-pulse');
        skeletons.forEach(skeleton => skeleton.remove());
    }
}

// Toast notification system with animations
class ToastManager {
    constructor() {
        this.container = document.getElementById('toast-container');
        this.toasts = new Map();
    }

    show(message, type = 'info', duration = 5000) {
        const toast = this.createToast(message, type);
        const id = Date.now().toString();
        
        this.toasts.set(id, toast);
        this.container.appendChild(toast);
        
        // Animate in
        requestAnimationFrame(() => {
            toast.style.transform = 'translateX(0)';
            toast.style.opacity = '1';
        });
        
        // Auto remove
        setTimeout(() => {
            this.hide(id);
        }, duration);
        
        return id;
    }

    createToast(message, type) {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.style.transform = 'translateX(100%)';
        toast.style.opacity = '0';
        toast.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
        
        const icon = this.getIcon(type);
        
        toast.innerHTML = `
            <i class="fas ${icon} text-lg"></i>
            <span class="flex-1">${message}</span>
            <button class="text-gray-400 hover:text-gray-600 ml-2" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        return toast;
    }

    getIcon(type) {
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };
        return icons[type] || icons.info;
    }

    hide(id) {
        const toast = this.toasts.get(id);
        if (toast) {
            toast.style.transform = 'translateX(100%)';
            toast.style.opacity = '0';
            
            setTimeout(() => {
                if (toast.parentElement) {
                    toast.parentElement.removeChild(toast);
                }
                this.toasts.delete(id);
            }, 300);
        }
    }

    success(message, duration) {
        return this.show(message, 'success', duration);
    }

    error(message, duration) {
        return this.show(message, 'error', duration);
    }

    warning(message, duration) {
        return this.show(message, 'warning', duration);
    }

    info(message, duration) {
        return this.show(message, 'info', duration);
    }
}

// Page transition effects
class PageTransitions {
    constructor() {
        this.currentPage = null;
    }

    async switchPage(fromElement, toElement, direction = 'left') {
        if (fromElement) {
            await this.animateOut(fromElement, direction);
            fromElement.classList.add('hidden');
        }
        
        toElement.classList.remove('hidden');
        await this.animateIn(toElement, direction);
        
        this.currentPage = toElement;
    }

    animateOut(element, direction) {
        return new Promise((resolve) => {
            const transform = direction === 'left' ? 'translateX(-100%)' : 'translateX(100%)';
            element.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
            element.style.transform = transform;
            element.style.opacity = '0';
            
            setTimeout(resolve, 300);
        });
    }

    animateIn(element, direction) {
        return new Promise((resolve) => {
            const initialTransform = direction === 'left' ? 'translateX(100%)' : 'translateX(-100%)';
            
            element.style.transform = initialTransform;
            element.style.opacity = '0';
            element.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
            
            requestAnimationFrame(() => {
                element.style.transform = 'translateX(0)';
                element.style.opacity = '1';
            });
            
            setTimeout(resolve, 300);
        });
    }
}

// Add CSS keyframes for animations
const style = document.createElement('style');
style.textContent = `
    @keyframes ripple {
        to {
            transform: scale(4);
            opacity: 0;
        }
    }
    
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        10%, 30%, 50%, 70%, 90% { transform: translateX(-10px); }
        20%, 40%, 60%, 80% { transform: translateX(10px); }
    }
    
    .animate-pulse-soft {
        animation: pulseSoft 2s ease-in-out infinite;
    }
`;
document.head.appendChild(style);

// Initialize global animation instances
window.animationManager = new AnimationManager();
window.toastManager = new ToastManager();
window.pageTransitions = new PageTransitions();

// Add ripple effect to all buttons
document.addEventListener('click', (event) => {
    if (event.target.matches('button, .btn-primary, .btn-secondary, .btn-danger, .btn-success')) {
        window.animationManager.createRipple(event, event.target);
        window.animationManager.bounceButton(event.target);
    }
});
