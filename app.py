# Flask 웹 개발에 필요한 기능을 가져옵니다.
from flask import Flask, render_template, request, redirect, url_for

# MySQL 연결에 사용하는 라이브러리입니다.
import pymysql

# .env 파일의 환경변수를 불러옵니다.
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)


# MySQL 데이터베이스에 연결하는 함수입니다.
def get_db_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor
    )


# 메시지에서 금융사기 위험요소를 분석하는 함수입니다.
def analyze_message(message):
    # 키워드마다 서로 다른 위험점수를 부여합니다.
    risk_keywords = {
        "송금": 15,
        "입금": 15,
        "계좌": 10,
        "비밀번호": 25,
        "인증번호": 25,
        "개인정보": 20,
        "신분증": 20,
        "검찰": 20,
        "경찰": 15,
        "금융감독원": 20,
        "대출": 15,
        "투자": 10,
        "수익 보장": 25,
        "원금 보장": 25,
        "당첨": 20,
        "앱 설치": 25,
        "링크": 15,
        "URL": 15,
        "즉시": 10,
        "긴급": 15,
        "차단": 10
    }

    score = 0
    detected_keywords = []

    # 입력된 메시지에 위험 키워드가 포함됐는지 확인합니다.
    for keyword, point in risk_keywords.items():
        if keyword.lower() in message.lower():
            score += point
            detected_keywords.append(keyword)

    # 인터넷 주소가 포함되면 위험점수를 추가합니다.
    if "http://" in message.lower() or "https://" in message.lower():
        score += 25
        detected_keywords.append("인터넷 주소")

    # 최종 점수는 최대 100점으로 제한합니다.
    score = min(score, 100)

    # 점수에 따라 위험등급을 결정합니다.
    if score >= 60:
        risk_level = "위험"
    elif score >= 30:
        risk_level = "주의"
    else:
        risk_level = "낮음"

    return score, risk_level, detected_keywords


# 메인 대시보드와 분석 기록 목록을 표시합니다.
@app.route("/")
def index():
    keyword = request.args.get("keyword", "").strip()
    scam_type = request.args.get("scam_type", "").strip()
    risk_level = request.args.get("risk_level", "").strip()

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            sql = "SELECT * FROM fraud_reports WHERE 1=1"
            values = []

            # 검색어가 있으면 메시지와 메모에서 검색합니다.
            if keyword:
                sql += " AND (message LIKE %s OR memo LIKE %s)"
                search_word = f"%{keyword}%"
                values.extend([search_word, search_word])

            # 선택된 사기 유형으로 필터링합니다.
            if scam_type:
                sql += " AND scam_type = %s"
                values.append(scam_type)

            # 선택된 위험등급으로 필터링합니다.
            if risk_level:
                sql += " AND risk_level = %s"
                values.append(risk_level)

            sql += " ORDER BY id DESC"

            cursor.execute(sql, values)
            reports = cursor.fetchall()

            # 대시보드 통계를 조회합니다.
            cursor.execute("SELECT COUNT(*) AS count FROM fraud_reports")
            total_count = cursor.fetchone()["count"]

            cursor.execute(
                "SELECT COUNT(*) AS count FROM fraud_reports "
                "WHERE risk_level = %s",
                ("위험",)
            )
            danger_count = cursor.fetchone()["count"]

            cursor.execute(
                "SELECT COUNT(*) AS count FROM fraud_reports "
                "WHERE risk_level = %s",
                ("주의",)
            )
            warning_count = cursor.fetchone()["count"]

            cursor.execute(
                "SELECT COUNT(*) AS count FROM fraud_reports "
                "WHERE risk_level = %s",
                ("낮음",)
            )
            low_count = cursor.fetchone()["count"]

    finally:
        connection.close()

    return render_template(
        "index.html",
        reports=reports,
        total_count=total_count,
        danger_count=danger_count,
        warning_count=warning_count,
        low_count=low_count,
        keyword=keyword,
        selected_type=scam_type,
        selected_level=risk_level
    )


# 새로운 의심 메시지를 분석하고 저장합니다.
@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    if request.method == "POST":
        message = request.form["message"].strip()
        scam_type = request.form["scam_type"]
        memo = request.form.get("memo", "").strip()

        # 위험점수와 등급을 계산합니다.
        risk_score, risk_level, detected = analyze_message(message)
        detected_keywords = ", ".join(detected)

        connection = get_db_connection()

        try:
            with connection.cursor() as cursor:
                sql = """
                    INSERT INTO fraud_reports
                    (
                        message,
                        scam_type,
                        risk_score,
                        risk_level,
                        detected_keywords,
                        memo
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                """
                cursor.execute(
                    sql,
                    (
                        message,
                        scam_type,
                        risk_score,
                        risk_level,
                        detected_keywords,
                        memo
                    )
                )
                connection.commit()

                # 방금 저장된 분석 기록의 번호를 가져옵니다.
                report_id = cursor.lastrowid

        finally:
            connection.close()

        return redirect(url_for("detail", report_id=report_id))

    return render_template("write.html")


# 분석 결과 상세 페이지입니다.
@app.route("/report/<int:report_id>")
def detail(report_id):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            sql = "SELECT * FROM fraud_reports WHERE id = %s"
            cursor.execute(sql, (report_id,))
            report = cursor.fetchone()
    finally:
        connection.close()

    return render_template("detail.html", report=report)


# 기존 분석 기록을 수정하고 다시 분석합니다.
@app.route("/edit/<int:report_id>", methods=["GET", "POST"])
def edit(report_id):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            if request.method == "POST":
                message = request.form["message"].strip()
                scam_type = request.form["scam_type"]
                memo = request.form.get("memo", "").strip()

                # 수정된 메시지로 위험도를 다시 계산합니다.
                risk_score, risk_level, detected = analyze_message(message)
                detected_keywords = ", ".join(detected)

                sql = """
                    UPDATE fraud_reports
                    SET message = %s,
                        scam_type = %s,
                        risk_score = %s,
                        risk_level = %s,
                        detected_keywords = %s,
                        memo = %s
                    WHERE id = %s
                """
                cursor.execute(
                    sql,
                    (
                        message,
                        scam_type,
                        risk_score,
                        risk_level,
                        detected_keywords,
                        memo,
                        report_id
                    )
                )
                connection.commit()

                return redirect(
                    url_for("detail", report_id=report_id)
                )

            sql = "SELECT * FROM fraud_reports WHERE id = %s"
            cursor.execute(sql, (report_id,))
            report = cursor.fetchone()

    finally:
        connection.close()

    return render_template("edit.html", report=report)


# 선택한 분석 기록을 삭제합니다.
@app.route("/delete/<int:report_id>", methods=["POST"])
def delete(report_id):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            sql = "DELETE FROM fraud_reports WHERE id = %s"
            cursor.execute(sql, (report_id,))
            connection.commit()
    finally:
        connection.close()

    return redirect(url_for("index"))


# app.py를 직접 실행하면 Flask 서버를 시작합니다.
if __name__ == "__main__":
    app.run(debug=True)