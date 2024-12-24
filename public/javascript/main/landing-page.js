document.addEventListener('mousemove', function (e) {
    let spiral = document.createElement('div');
    spiral.className = 'spiral';
    spiral.style.width = '100px';
    spiral.style.height = '100px';
    spiral.style.top = (e.clientY - 50) + 'px';
    spiral.style.left = (e.clientX - 50) + 'px';

    document.getElementById('backgroundEffect').appendChild(spiral);

    setTimeout(function () {
        spiral.remove();
    }, 1000); // The same duration as the fadeOut animation
});

