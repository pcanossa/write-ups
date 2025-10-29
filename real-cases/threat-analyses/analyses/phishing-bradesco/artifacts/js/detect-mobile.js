// JavaScript source code

var GetMobile = function () {
    var userAgent = navigator.userAgent || navigator.vendor || window.opera;
    if (/windows phone/i.test(userAgent)) {
        return 'Windows Phone';
    }

    if (/android/i.test(userAgent)) {
        return 'Android';
    }

    if (/iPad|iPhone|iPod/.test(userAgent) && !window.MSStream) {
        return 'iOS';
    }
    return 'unknown';
};

var OS = {
    change: function () {
        var currentOS = GetMobile();

        if (currentOS === 'iOS') {
            this.ios();
        }

        if (currentOS === 'Android') {
            this.android();
        }
    },
    ios: function () {

        var cdservicomobile =  $('[data-cdservico-mobile]'); 

        if (cdservicomobile != "" && cdservicomobile != null)
            $('[data-cdservico-mobile]').each(function() {
                var cdservicomobilevalor = $(this).attr('data-cdservico-mobile');
                $(this).attr('href', 'https://www.bradescocelular.com.br/app_redirect/index.html?deeplink=app/listadecontas' + '/?codigocampanha=' + cdservicomobilevalor);
            });
        else
            $('a[data-mobile-link]').attr('href', 'https://www.bradescocelular.com.br/app_redirect/index.html?deeplink=app/listadecontas');
            $('a[data-mobile-link]').removeClass('modalIB');
    },
    android: function () {
        var cdservicomobile = $('a[data-cdservico-mobile]');

        if (cdservicomobile != "" && cdservicomobile != null)
            $('[data-cdservico-mobile]').each(function() {
                var cdservicomobilevalor = $(this).attr('data-cdservico-mobile');
                $(this).attr('href', 'https://www.bradescocelular.com.br/app_redirect/index.html?deeplink=app/listadecontas' + '/?codigocampanha=' + cdservicomobilevalor);
            });
        else
            $('a[data-mobile-link]').attr('href', 'https://www.bradescocelular.com.br/app_redirect/index.html?deeplink=app/listadecontas');
            $('a[data-mobile-link]').removeClass('modalIB');
    },
    desk: function () { }
};

OS.change();