window.onload = () => {
    const button = document.createElement('a');
    button.innerHTML = '<i class="fas fa-arrow-up"></i>';
    button.href = '#';
    button.classList.add('scroll-button');
    document.body.appendChild(button);
}