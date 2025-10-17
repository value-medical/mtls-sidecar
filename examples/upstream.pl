:- use_module(library(http/http_server)).
:- use_module(library(http/json)).
:- use_module(library(base64)).

:- initialization
    http_server([port(8080)]).

:- http_handler(root(.), root_page, []).

root_page(Request) :-
    member(x_client_tls_info(TlsInfoBase64), Request),
    base64_encoded(TlsInfoStr, TlsInfoBase64, []),
    atom_json_dict(TlsInfoStr, TlsInfo, []),
    get_dict(subject, TlsInfo, Subject),
    reply_html_page([], [ p(['Client Subject: ', Subject]) ]).

