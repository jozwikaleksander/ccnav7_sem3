document.addEventListener('DOMContentLoaded', function() {
    const toc = document.querySelector('#TOC');
    const tocMenu = toc.cloneNode(true);
    tocMenu.classList.add('toc-menu');
    tocMenu.classList.remove('toc');
    tocMenu.classList.add('disabled');
    document.body.appendChild(tocMenu);
    
    tocMenu.addEventListener('click', (e) => {
        if(e.target.tagName === 'A'){
            tocMenu.classList.add('disabled');
        }
    });

    const menu = document.createElement('div');
    menu.classList.add('menu');
    document.body.appendChild(menu);

    const scrollBtn = document.createElement('a');
    scrollBtn.innerHTML = '<i class="fas fa-arrow-up"></i>';
    scrollBtn.href = '#';
    scrollBtn.classList.add('scroll-button');
    menu.appendChild(scrollBtn);

    const tocBtn = document.createElement('a');
    tocBtn.innerHTML = '<i class="fas fa-list"></i>';
    tocBtn.classList.add('toc-button');
    menu.appendChild(tocBtn);

    tocBtn.addEventListener('click', () => {
        tocMenu.classList.toggle('disabled');
    });

    document.addEventListener('click', (e) => {
        if(!tocMenu.contains(e.target) && !tocBtn.contains(e.target)){
            tocMenu.classList.add('disabled');
        }
    });
 }, false);