// 최지원 정보보안 컨설턴트 포트폴리오 - 깔끔한 JavaScript

document.addEventListener('DOMContentLoaded', function() {
    initNavigation();
    initProjectFilter();
    initScrollAnimations();
    initContactInteraction();
    initTechStack(); // 🔥 기술스택 기능 추가
    
    console.log('🌟 최지원 정보보안 컨설턴트 포트폴리오가 로드되었습니다.');
});

/**
 * 네비게이션 기능
 */
function initNavigation() {
    // 부드러운 스크롤
    const navLinks = document.querySelectorAll('.nav-link[href^="#"]');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            const targetSection = document.querySelector(targetId);
            
            if (targetSection) {
                const navbarHeight = 80;
                const targetPosition = targetSection.offsetTop - navbarHeight;
                
                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });
                
                // 모바일 메뉴 닫기
                const navbarCollapse = document.querySelector('.navbar-collapse');
                if (navbarCollapse && navbarCollapse.classList.contains('show')) {
                    const navbarToggler = document.querySelector('.navbar-toggler');
                    if (navbarToggler) navbarToggler.click();
                }
            }
        });
    });
    
    // 스크롤 시 활성 메뉴 업데이트
    window.addEventListener('scroll', updateActiveNavItem);
}

/**
 * 활성 네비게이션 아이템 업데이트
 */
function updateActiveNavItem() {
    const sections = document.querySelectorAll('section[id]');
    const navLinks = document.querySelectorAll('.nav-link[href^="#"]');
    const scrollPosition = window.scrollY + 150;
    
    sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.offsetHeight;
        const sectionId = section.getAttribute('id');
        
        if (scrollPosition >= sectionTop && scrollPosition < sectionTop + sectionHeight) {
            navLinks.forEach(link => link.classList.remove('active'));
            
            const activeLink = document.querySelector(`.nav-link[href="#${sectionId}"]`);
            if (activeLink) {
                activeLink.classList.add('active');
            }
        }
    });
}

/**
 * 프로젝트 필터링
 */
function initProjectFilter() {
    const filterButtons = document.querySelectorAll('.filter-btn');
    const projectItems = document.querySelectorAll('.project-item');
    
    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            const filter = this.getAttribute('data-filter');
            
            // 활성 버튼 업데이트
            filterButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            
            // 프로젝트 필터링
            projectItems.forEach((item, index) => {
                const categories = item.getAttribute('data-category');
                
                if (filter === 'all' || categories.includes(filter)) {
                    item.style.display = 'block';
                    item.classList.remove('hidden');
                    
                    // 순차 애니메이션
                    setTimeout(() => {
                        item.style.opacity = '1';
                        item.style.transform = 'scale(1)';
                    }, index * 100);
                } else {
                    item.classList.add('hidden');
                    
                    setTimeout(() => {
                        item.style.display = 'none';
                    }, 400);
                }
            });
            
            // 필터링 완료 알림
            showNotification(`${getFilterName(filter)} 프로젝트를 표시합니다.`);
        });
    });
}

/**
 * 필터명 반환
 */
function getFilterName(filter) {
    const filterNames = {
        'all': '전체',
        'web': '웹 보안',
        'app': '앱 보안',
        'cloud': '클라우드 보안',
        'api': 'API 보안'
    };
    return filterNames[filter] || '프로젝트';
}

/**
 * 스크롤 애니메이션
 */
function initScrollAnimations() {
    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const element = entry.target;
                
                // 통계 숫자 애니메이션
                if (element.classList.contains('stat-number')) {
                    animateNumber(element);
                }
                
                // 요소 표시 애니메이션
                element.style.opacity = '1';
                element.style.transform = 'translateY(0)';
                
                observer.unobserve(element);
            }
        });
    }, {
        threshold: 0.2,
        rootMargin: '0px 0px -50px 0px'
    });
    
    // 애니메이션 대상 요소들
    const animateElements = document.querySelectorAll('.stat-number, .service-card, .project-card, .timeline-item, .contact-item');
    animateElements.forEach(element => {
        element.style.opacity = '0';
        element.style.transform = 'translateY(20px)';
        element.style.transition = 'all 0.6s ease';
        observer.observe(element);
    });
}

/**
 * 숫자 애니메이션
 */
function animateNumber(element) {
    const targetText = element.textContent;
    const targetNumber = parseFloat(targetText.replace(/[^0-9.]/g, ''));
    const suffix = targetText.replace(/[0-9.]/g, '');
    
    if (isNaN(targetNumber)) return;
    
    let currentNumber = 0;
    const increment = targetNumber / 30;
    const duration = 1200;
    const stepTime = duration / 30;
    
    const timer = setInterval(() => {
        currentNumber += increment;
        
        if (currentNumber >= targetNumber) {
            element.textContent = targetText;
            clearInterval(timer);
        } else {
            if (targetText.includes('.')) {
                element.textContent = currentNumber.toFixed(1) + suffix;
            } else {
                element.textContent = Math.floor(currentNumber) + suffix;
            }
        }
    }, stepTime);
}

/**
 * 연락처 상호작용
 */
function initContactInteraction() {
    const contactItems = document.querySelectorAll('.contact-item');
    
    contactItems.forEach(item => {
        item.addEventListener('click', function() {
            const icon = this.querySelector('i');
            let message = '';
            
            if (icon.classList.contains('bi-envelope')) {
                message = '이메일 문의를 원하시면 포트폴리오를 통해 연락처를 확인해주세요! 📧';
            } else if (icon.classList.contains('bi-telephone')) {
                message = '정보보안 컨설팅 관련 문의는 언제든 연락해주세요! 📞';
            } else if (icon.classList.contains('bi-linkedin')) {
                message = 'LinkedIn을 통해 네트워킹해보세요! 💼';
            }
            
            if (message) {
                showNotification(message);
            }
        });
    });
}

/**
 * 🔥 기술스택 초기화 (새로 추가)
 */
function initTechStack() {
    const techItems = document.querySelectorAll('.tech-item');
    
    const techDescriptions = {
        'Web': '웹 애플리케이션 보안 진단 및 취약점 분석',
        'Mobile': 'iOS/Android 모바일 앱 보안성 검토',
        'Cloud': 'AWS/Azure 클라우드 인프라 보안 검토',
        'AI': 'AI 보안 및 Prompt Injection 취약점 연구',
        'Python': '보안 도구 개발 및 자동화 스크립팅',
        'JavaScript': '웹 보안 진단 및 클라이언트 사이드 분석'
    };
    
    techItems.forEach(item => {
        // 클릭 이벤트
        item.addEventListener('click', function() {
            const techName = this.querySelector('.tech-name').textContent;
            const description = techDescriptions[techName];
            
            if (description) {
                showTechNotification(techName, description);
            }
        });
        
        // 키보드 접근성
        item.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                this.click();
            }
        });
    });
}

/**
 * 🔥 기술스택 알림 표시 (새로 추가)
 */
function showTechNotification(techName, description) {
    // 기존 알림 제거
    const existingNotification = document.querySelector('.tech-notification');
    if (existingNotification) {
        existingNotification.remove();
    }
    
    // 새 알림 생성
    const notification = document.createElement('div');
    notification.className = 'tech-notification';
    notification.innerHTML = `
        <div class="notification-header">
            💻 ${techName}
        </div>
        <div class="notification-body">
            ${description}
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // 애니메이션으로 표시
    setTimeout(() => {
        if (window.innerWidth <= 768) {
            notification.style.transform = 'translateY(0)';
        } else {
            notification.style.transform = 'translateX(0)';
        }
    }, 100);
    
    // 4초 후 자동 제거
    setTimeout(() => {
        if (window.innerWidth <= 768) {
            notification.style.transform = 'translateY(-100%)';
        } else {
            notification.style.transform = 'translateX(100%)';
        }
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 300);
    }, 4000);
}

/**
 * 알림 메시지 표시
 */
function showNotification(message) {
    // 기존 알림 제거
    const existingNotification = document.querySelector('.notification');
    if (existingNotification) {
        existingNotification.remove();
    }
    
    // 새 알림 생성
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.textContent = message;
    
    // 스타일 적용
    Object.assign(notification.style, {
        position: 'fixed',
        top: '20px',
        right: '20px',
        background: 'white',
        color: '#2c3e50',
        padding: '15px 20px',
        borderRadius: '10px',
        fontSize: '14px',
        fontWeight: '500',
        zIndex: '9999',
        border: '1px solid #e8f6f3',
        boxShadow: '0 4px 20px rgba(32, 178, 170, 0.15)',
        transform: 'translateX(100%)',
        transition: 'transform 0.3s ease',
        maxWidth: '320px',
        lineHeight: '1.4'
    });
    
    document.body.appendChild(notification);
    
    // 애니메이션으로 표시
    setTimeout(() => {
        notification.style.transform = 'translateX(0)';
    }, 100);
    
    // 3초 후 자동 제거
    setTimeout(() => {
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 300);
    }, 3000);
}

/**
 * 반응형 처리
 */
window.addEventListener('resize', function() {
    // 모바일에서 네비게이션 메뉴 자동 닫기
    if (window.innerWidth > 768) {
        const navbarCollapse = document.querySelector('.navbar-collapse');
        if (navbarCollapse && navbarCollapse.classList.contains('show')) {
            const navbarToggler = document.querySelector('.navbar-toggler');
            if (navbarToggler) navbarToggler.click();
        }
    }
});

/**
 * 키보드 접근성 (🔥 기술스택 지원 추가)
 */
document.addEventListener('keydown', function(e) {
    // ESC 키로 알림 닫기 (tech-notification 추가)
    if (e.key === 'Escape') {
        const notification = document.querySelector('.notification, .tech-notification');
        if (notification) {
            notification.remove();
        }
    }
    
    // 엔터 키로 연락처 아이템 및 기술스택 아이템 클릭 (tech-item 추가)
    if (e.key === 'Enter') {
        const focusedElement = document.activeElement;
        if (focusedElement && (focusedElement.classList.contains('contact-item') || focusedElement.classList.contains('tech-item'))) {
            focusedElement.click();
        }
    }
});

/**
 * 개발자 콘솔 메시지 (🔥 기술스택 정보 추가)
 */
console.log('%c🛡️ 최지원 정보보안 컨설턴트', 'color: #4a90e2; font-size: 18px; font-weight: bold;');
console.log('%c기술스택: Web, Mobile, Cloud, AI, Python, JavaScript 🚀', 'color: #32cd32; font-size: 14px;');
console.log('📧 이메일: jwc*******@naver.com');
console.log('📞 전화: 010-****-8782');
console.log('💻 기술스택 카드를 클릭해보세요!');
