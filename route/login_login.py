from .tool.func import *
from urllib.parse import urlparse

def login_login_2():
    with get_db_connect() as conn:
        curs = conn.cursor()

        ip = ip_check()
        if ip_or_user(ip) == 0:
            return redirect(conn, '/user')

        if ban_check(None, 'login')[0] == 1:
            return re_error(conn, 0)

        if flask.request.method == 'POST':
            # CAPTCHA 검증
            if captcha_post(conn, flask.request.form.get('g-recaptcha-response', flask.request.form.get('g-recaptcha', ''))) == 1:
                return re_error(conn, 13)

            user_agent = flask.request.headers.get('User-Agent', '')
            user_id = flask.request.form.get('id', '')
            user_pw = flask.request.form.get('pw', '')

            # 사용자 인증
            curs.execute(db_change("select data from user_set where id = ? and name = 'pw'"), [user_id])
            db_data = curs.fetchall()
            if not db_data:
                return re_error(conn, 2)
            else:
                db_user_pw = db_data[0][0]

            curs.execute(db_change("select data from user_set where id = ? and name = 'encode'"), [user_id])
            db_data = curs.fetchall()
            if not db_data:
                return re_error(conn, 2)
            else:
                db_user_encode = db_data[0][0]

            if pw_check(conn, user_pw, db_user_pw, db_user_encode, user_id) != 1:
                return re_error(conn, 10)

            # 2FA 확인
            curs.execute(db_change('select data from user_set where name = "2fa" and id = ?'), [user_id])
            fa_data = curs.fetchall()
            if fa_data and fa_data[0][0] != '':
                flask.session['login_id'] = user_id
                return redirect(conn, '/login/2fa')
            else:
                # 로그인 성공 처리
                flask.session['id'] = user_id
                ua_plus(conn, user_id, ip, user_agent, get_time())

                # 세션에서 이전 URL 가져오기
                redirect_url = flask.session.get('redirect_url', '/user')
                if not is_safe_url(redirect_url):
                    redirect_url = '/user'

                return redirect(conn, redirect_url)
        else:
            # GET 요청 시 이전 URL 저장
            referrer = flask.request.referrer
            if referrer and is_safe_url(referrer):
                flask.session['redirect_url'] = referrer
            else:
                flask.session['redirect_url'] = '/user'

            # 로그인 폼 렌더링
            return easy_minify(conn, flask.render_template(skin_check(conn),
                imp = [get_lang(conn, 'login'), wiki_set(conn), wiki_custom(conn), wiki_css([0, 0])],
                data = '''
                        <form method="post">
                            <input placeholder="''' + get_lang(conn, 'id') + '''" name="id" type="text">
                            <hr class="main_hr">
                            <input placeholder="''' + get_lang(conn, 'password') + '''" name="pw" type="password">
                            <hr class="main_hr">
                            ''' + captcha_get(conn) + '''
                            <button type="submit">''' + get_lang(conn, 'login') + '''</button>
                            ''' + http_warning(conn) + '''
                        </form>
                        ''',
                menu = [['user', get_lang(conn, 'return')]]
            ))

# URL 안전 검증 함수
def is_safe_url(target):
    from urllib.parse import urlparse
    if not target:
        return False
    ref_url = urlparse(flask.request.host_url)
    test_url = urlparse(target)
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc
