document.addEventListener('DOMContentLoaded', function() {
  // Animation au scroll
  const animateOnScroll = () => {
    const elements = document.querySelectorAll('.service-item, .reason-item');
    
    elements.forEach(element => {
      const elementPosition = element.getBoundingClientRect().top;
      const screenPosition = window.innerHeight / 1.2;
      
      if (elementPosition < screenPosition) {
        element.style.opacity = '1';
        element.style.transform = 'translateY(0)';
      }
    });
  };
  
  // Initial state for animation
  const serviceItems = document.querySelectorAll('.service-item');
  const reasonItems = document.querySelectorAll('.reason-item');
  
  serviceItems.forEach(item => {
    item.style.opacity = '0';
    item.style.transform = 'translateY(20px)';
    item.style.transition = 'all 0.6s ease';
  });
  
  reasonItems.forEach(item => {
    item.style.opacity = '0';
    item.style.transform = 'translateY(20px)';
    item.style.transition = 'all 0.6s ease';
  });
  
  // Trigger animation on load and scroll
  animateOnScroll();
  window.addEventListener('scroll', animateOnScroll);
  
  // Smooth scrolling for anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({ behavior: 'smooth' });
      }
    });
  });
  
  // Toggle 'more-info' sections on reason-item titles click (accordéon)
  document.querySelectorAll('.reason-item h3').forEach(title => {
    title.addEventListener('click', () => {
      const moreInfo = title.parentElement.querySelector('.more-info');
      if (moreInfo.style.maxHeight) {
        moreInfo.style.maxHeight = null;
      } else {
        moreInfo.style.maxHeight = moreInfo.scrollHeight + "px";
      }
    });
  });
  
  // Gestion affichage des formulaires connexion / inscription
  const showRegisterLink = document.getElementById('show-register');
  const showLoginLink = document.getElementById('show-login');
  const loginContainer = document.getElementById('login-container');
  const registerContainer = document.getElementById('register-container');

  function showRegister() {
    loginContainer.style.display = 'none';
    registerContainer.style.display = 'block';
    registerContainer.style.opacity = '0';
    registerContainer.style.transform = 'translateY(20px)';
    setTimeout(() => {
      registerContainer.style.opacity = '1';
      registerContainer.style.transform = 'translateY(0)';
    }, 10);
  }

  function showLogin() {
    registerContainer.style.display = 'none';
    loginContainer.style.display = 'block';
    loginContainer.style.opacity = '0';
    loginContainer.style.transform = 'translateY(20px)';
    setTimeout(() => {
      loginContainer.style.opacity = '1';
      loginContainer.style.transform = 'translateY(0)';
    }, 10);
  }

  if (showRegisterLink) {
    showRegisterLink.addEventListener('click', function(e) {
      e.preventDefault();
      showRegister();
    });
  }

  if (showLoginLink) {
    showLoginLink.addEventListener('click', function(e) {
      e.preventDefault();
      showLogin();
    });
  }
});
document.querySelectorAll('.menu-button, .action-btn, .widget, .reminder-item, .fab').forEach(button => {
  button.addEventListener('click', function() {
    this.classList.toggle('active');
  });
});
 const cursor = document.querySelector('.cursor');
    const cursorFollower = document.querySelector('.cursor-follower');

    document.addEventListener('mousemove', (e) => {
      cursor.style.left = e.clientX + 'px';
      cursor.style.top = e.clientY + 'px';
      
      setTimeout(() => {
        cursorFollower.style.left = e.clientX + 'px';
        cursorFollower.style.top = e.clientY + 'px';
      }, 100);
    });

    // Cursor interaction
    document.addEventListener('mouseenter', () => {
      cursor.style.display = 'block';
      cursorFollower.style.display = 'block';
    });

    document.addEventListener('mouseleave', () => {
      cursor.style.display = 'none';
      cursorFollower.style.display = 'none';
    });

    // Hover effects
    document.querySelectorAll('a, button, .service-card').forEach(el => {
      el.addEventListener('mouseenter', () => {
        cursor.style.transform = 'scale(1.5)';
        cursorFollower.style.transform = 'scale(2)';
      });
      
      el.addEventListener('mouseleave', () => {
        cursor.style.transform = 'scale(1)';
        cursorFollower.style.transform = 'scale(1)';
      });
    });

    // Image following cursor effect
    document.querySelectorAll('[cursor-following]').forEach(el => {
  // Add transition for smooth effect
  el.style.transition = 'transform 0.5s cubic-bezier(0.03, 0.98, 0.52, 0.99)';
  
  // Add perspective to parent for better 3D
  el.style.transformStyle = 'preserve-3d';
  
  el.addEventListener('mousemove', (e) => {
    const rect = el.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    
    // Calculate rotation based on mouse position (more pronounced effect)
    const rotateX = ((y - centerY) / centerY) * 10; // Increased from 10 to 15 for more tilt
    const rotateY = ((centerX - x) / centerX) * -10; // Inverted for more natural movement
    
    // Add slight scale and Z translation on hover
    el.style.transform = `
      perspective(1000px) 
      rotateX(${rotateX}deg) 
      rotateY(${rotateY}deg) 
      translateZ(30px)
      scale(1.03)`;
      
    // Optional: Add subtle shadow/glow effect
    el.style.boxShadow = `
      ${rotateY * -1}px ${rotateX * -1}px 30px rgba(0, 0, 0, 0.2)`;
  });
  
  el.addEventListener('mouseleave', () => {
    // Smooth return to original state
    el.style.transform = `
      perspective(1000px) 
      rotateX(0deg) 
      rotateY(0deg) 
      translateZ(0px)
      scale(1)`;
      
    // Remove shadow
    el.style.boxShadow = 'none';
  });
});

    // Login/Register toggle
    const showRegister = document.getElementById('show-register');
    const showLogin = document.getElementById('show-login');
    const loginContainer = document.getElementById('login-container');
    const registerContainer = document.getElementById('register-container');

    showRegister.addEventListener('click', (e) => {
      e.preventDefault();
      loginContainer.style.display = 'none';
      registerContainer.style.display = 'block';
    });

    showLogin.addEventListener('click', (e) => {
      e.preventDefault();
      registerContainer.style.display = 'none';
      loginContainer.style.display = 'block';
    });

    // Smooth scrolling
    document.querySelectorAll('[data-scroll]').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const targetId = link.getAttribute('data-scroll');
        const target = document.getElementById(targetId);
        if (target) {
          target.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
          });
        }
      });
    });

    // Scroll animations
    const observerOptions = {
      threshold: 0.1,
      rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
        }
      });
    }, observerOptions);

    document.querySelectorAll('.fade-in').forEach(el => {
      observer.observe(el);
    });


    // Enhanced service card interactions
    document.querySelectorAll('.service-card').forEach(card => {
      card.addEventListener('mousemove', (e) => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        
        const centerX = rect.width / 2;
        const centerY = rect.height / 2;
        
        const rotateX = (y - centerY) / 20;
        const rotateY = (centerX - x) / 20;
        
        card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-10px) translateZ(20px)`;
      });
      
      card.addEventListener('mouseleave', () => {
        card.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) translateY(0px) translateZ(0px)';
      });
    });

    // Form enhancements
    document.querySelectorAll('input').forEach(input => {
      input.addEventListener('focus', () => {
        input.parentElement.style.transform = 'translateY(-2px)';
      });
      
      input.addEventListener('blur', () => {
        input.parentElement.style.transform = 'translateY(0px)';
      });
    });

    // Add loading animation to buttons
    document.querySelectorAll('.btn-login, .btn-register').forEach(btn => {
      btn.addEventListener('click', () => {
        btn.style.transform = 'scale(0.95)';
        setTimeout(() => {
          btn.style.transform = 'scale(1)';
        }, 150);
      });
    });
    