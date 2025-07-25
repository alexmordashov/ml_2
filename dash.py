import pandas as pd
import streamlit as st
import altair as alt
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, confusion_matrix, recall_score
import seaborn as sns
import joblib
import matplotlib.pyplot as plt
import shap
import json
import numpy as np
import plotly.express as px
import statsmodels.api as sm
import xgboost as xgb


def main():
    st.set_page_config(layout="wide", page_title="Анализ защищённости сайтов")
    data_fruit = pd.read_csv("data1.csv")

    def load_model():
        model = joblib.load('sites_model.pkl')
        return model

    def load_metrics():
        metrics_df = pd.read_csv('metrics.csv')
        return metrics_df

    metrics = load_metrics()
    model = load_model()

    def load_test_x():
        with open('test_data.json', 'r') as f:
            test_data = json.load(f)
        X_test = pd.DataFrame(test_data["x_test"])
        return X_test

    def load_test_y():
        with open('test_data.json', 'r') as f:
            test_data = json.load(f)
        y_test = pd.DataFrame(test_data["y_test"])
        return y_test

    def load_pred_y():
        with open('test_data.json', 'r') as f:
            test_data = json.load(f)
        y_pred = pd.DataFrame(test_data["y_pred"])
        return y_pred

    def load_features():
        with open('model_metadata.json', 'r') as f:
            test_data = json.load(f)
        return test_data["features"]

    features = load_features()
    X_test = load_test_x()
    y_test = load_test_y()
    y_pred = load_pred_y()

    col1, col2, col3 = st.columns([7, 7, 7])

    with col2:
        st.title("Антивирус")
    st.title("Беспечалов Артём Александрович 2023-ФГиИБ-ПИ-1б 2 Вариант")
    st.write("Цель моей работы: на основе характеристик сайтов анализировать их защищённость.")

    tab1, tab2, tab3, tab4 = st.tabs(["Исходные данные", "Графики зависимостей", "Матрица ошибок и метрики модели",
                                      "Интерпретация результатов обучения модели"])

    with tab4:
        col1, col2 = st.columns(2)

        with col1:
            explainer = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(X_test)
            st.subheader("SHAP-значения признаков")
            fig, ax = plt.subplots(figsize=(10, 6))
            shap.summary_plot(shap_values, X_test, plot_type="bar", show=False)
            st.pyplot(fig, bbox_inches='tight')
            plt.close()

        with col2:
            st.subheader("SHAP-анализ")
            explainer = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(X_test)
            plt.figure(figsize=(6, 4))
            shap.summary_plot(
                shap_values,
                X_test,
                feature_names=features,
                plot_type="dot",
                show=False,
                max_display=min(20, len(features)))
            plt.tight_layout()
            st.pyplot(plt.gcf())
            plt.close()
            st.write('Интерпретация:')
            st.write('- Красные точки: высокие значения признака увеличивают вероятность класса "0"')
            st.write('- Синие точки: низкие значения уменьшают вероятность класса "0"')

    with tab2:
        col1, col2 = st.columns(2)
        with col1:
            st.header("1. Распределение признаков")
            feature = st.selectbox('Выберите признак:', ['URL_LENGTH', 'NUMBER_SPECIAL_CHARACTERS',
       'CONTENT_LENGTH', 'TCP_CONVERSATION_EXCHANGE', 'DIST_REMOTE_TCP_PORT',
       'REMOTE_IPS', 'APP_BYTES', 'SOURCE_APP_PACKETS', 'REMOTE_APP_PACKETS',
       'SOURCE_APP_BYTES', 'REMOTE_APP_BYTES', 'APP_PACKETS',
       'DNS_QUERY_TIMES', 'CHARSET_ISO-8859-1', 'CHARSET_UTF-8',
       'CHARSET_iso-8859-1', 'CHARSET_us-ascii', 'CHARSET_utf-8',
       'CHARSET_windows-1251', 'CHARSET_windows-1252', 'WHOIS_COUNTRY_GB',
       'WHOIS_COUNTRY_group1', 'WHOIS_COUNTRY_group2', 'WHOIS_COUNTRY_group3',
       'WHOIS_COUNTRY_group4', 'WHOIS_COUNTRY_group5', 'WHOIS_COUNTRY_group6',
       'WHOIS_STATEPRO_CA', 'WHOIS_STATEPRO_group1', 'WHOIS_STATEPRO_group2',
       'WHOIS_STATEPRO_group3', 'WHOIS_STATEPRO_group4',
       'WHOIS_STATEPRO_group5', 'WHOIS_STATEPRO_group6',
       'WHOIS_STATEPRO_group7', 'WHOIS_STATEPRO_group8',
       'WHOIS_STATEPRO_group9', 'WHOIS_REGDATE_3/03/2000 0:00',
       'WHOIS_REGDATE_group1', 'WHOIS_REGDATE_group2', 'WHOIS_REGDATE_group3',
       'WHOIS_UPDATED_DATE_group1', 'WHOIS_UPDATED_DATE_group2',
       'WHOIS_UPDATED_DATE_group3', 'WHOIS_UPDATED_DATE_group4',
       'WHOIS_UPDATED_DATE_group5', 'WHOIS_UPDATED_DATE_group6',
       'WHOIS_UPDATED_DATE_group7', 'WHOIS_UPDATED_DATE_group8'
                                                         ])
            color_scale = alt.Scale(
                domain=['0', '1'],
                range=['green', 'red']
            )
            sorted_data = data_fruit.sort_values('Type', ascending=[False])
            hist = alt.Chart(sorted_data).mark_bar(
                opacity=0.5,
                binSpacing=0, stroke='black',
                strokeWidth=0.5
            ).encode(
                alt.X(f'{feature}:Q').bin(maxbins=50),
                alt.Y('count()').stack(None),
                alt.Color('Type:N', scale=color_scale,
                          legend=alt.Legend(title="Защищённость")),
                tooltip=['count()', 'Type'],
                order=alt.Order('Type', sort='descending')
            ).properties(
                width=600,
                height=400
            ).interactive()
            st.altair_chart(hist, use_container_width=True)

        with col2:
            st.header("2. Зависимость")
            x_axis = st.selectbox(
                'Выберите признак для оси X:',
                ['URL_LENGTH', 'NUMBER_SPECIAL_CHARACTERS',
       'CONTENT_LENGTH', 'TCP_CONVERSATION_EXCHANGE', 'DIST_REMOTE_TCP_PORT',
       'REMOTE_IPS', 'APP_BYTES', 'SOURCE_APP_PACKETS', 'REMOTE_APP_PACKETS',
       'SOURCE_APP_BYTES', 'REMOTE_APP_BYTES', 'APP_PACKETS',
       'DNS_QUERY_TIMES', 'CHARSET_ISO-8859-1', 'CHARSET_UTF-8',
       'CHARSET_iso-8859-1', 'CHARSET_us-ascii', 'CHARSET_utf-8',
       'CHARSET_windows-1251', 'CHARSET_windows-1252', 'WHOIS_COUNTRY_GB',
       'WHOIS_COUNTRY_group1', 'WHOIS_COUNTRY_group2', 'WHOIS_COUNTRY_group3',
       'WHOIS_COUNTRY_group4', 'WHOIS_COUNTRY_group5', 'WHOIS_COUNTRY_group6',
       'WHOIS_STATEPRO_CA', 'WHOIS_STATEPRO_group1', 'WHOIS_STATEPRO_group2',
       'WHOIS_STATEPRO_group3', 'WHOIS_STATEPRO_group4',
       'WHOIS_STATEPRO_group5', 'WHOIS_STATEPRO_group6',
       'WHOIS_STATEPRO_group7', 'WHOIS_STATEPRO_group8',
       'WHOIS_STATEPRO_group9', 'WHOIS_REGDATE_3/03/2000 0:00',
       'WHOIS_REGDATE_group1', 'WHOIS_REGDATE_group2', 'WHOIS_REGDATE_group3',
       'WHOIS_UPDATED_DATE_group1', 'WHOIS_UPDATED_DATE_group2',
       'WHOIS_UPDATED_DATE_group3', 'WHOIS_UPDATED_DATE_group4',
       'WHOIS_UPDATED_DATE_group5', 'WHOIS_UPDATED_DATE_group6',
       'WHOIS_UPDATED_DATE_group7', 'WHOIS_UPDATED_DATE_group8'
                 ],
                index=5,
                key='x_axis'
            )
            y_axis = st.selectbox(
                'Выберите признак для оси Y:',
                ['URL_LENGTH', 'NUMBER_SPECIAL_CHARACTERS',
       'CONTENT_LENGTH', 'TCP_CONVERSATION_EXCHANGE', 'DIST_REMOTE_TCP_PORT',
       'REMOTE_IPS', 'APP_BYTES', 'SOURCE_APP_PACKETS', 'REMOTE_APP_PACKETS',
       'SOURCE_APP_BYTES', 'REMOTE_APP_BYTES', 'APP_PACKETS',
       'DNS_QUERY_TIMES', 'CHARSET_ISO-8859-1', 'CHARSET_UTF-8',
       'CHARSET_iso-8859-1', 'CHARSET_us-ascii', 'CHARSET_utf-8',
       'CHARSET_windows-1251', 'CHARSET_windows-1252', 'WHOIS_COUNTRY_GB',
       'WHOIS_COUNTRY_group1', 'WHOIS_COUNTRY_group2', 'WHOIS_COUNTRY_group3',
       'WHOIS_COUNTRY_group4', 'WHOIS_COUNTRY_group5', 'WHOIS_COUNTRY_group6',
       'WHOIS_STATEPRO_CA', 'WHOIS_STATEPRO_group1', 'WHOIS_STATEPRO_group2',
       'WHOIS_STATEPRO_group3', 'WHOIS_STATEPRO_group4',
       'WHOIS_STATEPRO_group5', 'WHOIS_STATEPRO_group6',
       'WHOIS_STATEPRO_group7', 'WHOIS_STATEPRO_group8',
       'WHOIS_STATEPRO_group9', 'WHOIS_REGDATE_3/03/2000 0:00',
       'WHOIS_REGDATE_group1', 'WHOIS_REGDATE_group2', 'WHOIS_REGDATE_group3',
       'WHOIS_UPDATED_DATE_group1', 'WHOIS_UPDATED_DATE_group2',
       'WHOIS_UPDATED_DATE_group3', 'WHOIS_UPDATED_DATE_group4',
       'WHOIS_UPDATED_DATE_group5', 'WHOIS_UPDATED_DATE_group6',
       'WHOIS_UPDATED_DATE_group7', 'WHOIS_UPDATED_DATE_group8'
                 ],
                index=4,
                key='y_axis'
            )

            st.write(f"**Зависимость {y_axis} от {x_axis}**")

            fig = px.scatter(
                data_fruit,
                x=x_axis,
                y=y_axis,
                color='Type',
                color_discrete_map={'0': 'green', '1': 'red'},
                trendline="lowess",
                trendline_options=dict(frac=0.3),
                width=800,
                height=500
            )

            fig.update_layout(
                xaxis_title=f"{x_axis}",
                yaxis_title=f"{y_axis}",
                legend_title="Защищённость",
                hovermode='closest'
            )

            fig.update_traces(
                line=dict(width=4),
                marker=dict(size=1, opacity=0.5)
            )
            st.plotly_chart(fig, use_container_width=True)

    with tab3:
        final_matrix = confusion_matrix(y_test, y_pred)

        fig = px.imshow(final_matrix,
                        labels=dict(x="Предсказано", y="Истинное", color="Count"),
                        x=['Защищённые', 'Вредоносные'],
                        y=['Защищённые', 'Вредоносные'],
                        text_auto=True,
                        color_continuous_scale='Greens')
        fig.update_layout(title='Матрица ошибок')
        st.plotly_chart(fig)

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Тестовая Accuracy", f"{accuracy_score(y_test, y_pred):.4f}")

        with col2:
            st.metric("Test F1-score", f"{f1_score(y_test, y_pred):.4f}")

        with col3:
            st.metric("recall", f"{recall_score(y_test, y_pred):.4f}")
        # st.subheader("Отчёт классификации")
        # report = classification_report(y_test, y_pred, output_dict=True)
        # st.table(pd.DataFrame(report).transpose())

    with tab1:
        st.dataframe(data_fruit)

    return data_fruit


if __name__ == '__main__':
    main()


