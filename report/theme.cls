% stolen and revised from cs31 for use of cs157 by bniedzie
% Tue Nov 09 23:28:49 EST 2011

% updated for 2020 course (evelasq2)
% Mon Aug 31 20:54 EST 2020
% updated for 2022 course (rscheide)

\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{theme}[2012/01/08 v1.0 (bniedzie)]

\def\CS@probdir{/course/cs157/asgn/problems}

\def\LayoutTextField#1#2{#2} % override default in hyperref                                           
\def\answerline#1#2{\vbox{\hbox{\TextField[name=#1, height=10pt, width=#2]{\null}}}}
\def\answerbox#1{\vbox{\hbox{\TextField[multiline=true, name=#1, width=6.5in]{\null}}}}

\DeclareRobustCommand{\CS@classnum}{\textbf{CSCI 1570 - Fall 2022}}
\DeclareRobustCommand{\CS@classname}{Design and Analysis of Algorithms}
\DeclareRobustCommand{\CS@prof}{Lorenzo De Stefani}
\newcommand{\course}[3]{
    \DeclareRobustCommand{\CS@classnum}{\textbf{#1}}
    \DeclareRobustCommand{\CS@classname}{#2}
    \DeclareRobustCommand{\CS@prof}{#3}
}
\LoadClass{cs}[1998/06/08]
%
\parskip = 6pt
\parindent = 0pt

\usepackage{hyperref}
\usepackage{tikz}
\usepackage{graphicx}
\graphicspath{graphics}
\usepackage{listings}
\usepackage{booktabs}
\usepackage{graphicx}
\usepackage{multirow}
\usepackage{multicol}

\usepackage{amsmath}
\usepackage{amsfonts}
\usepackage{amssymb}
\usepackage{algorithm}
\usepackage{algpseudocode}
\usepackage[lighttt]{lmodern}
\makeatletter
\algrenewcommand\ALG@beginalgorithmic{\ttfamily}
\makeatother

\usepackage[noframe]{showframe}
\usepackage{framed}
\usepackage[shortlabels]{enumitem}

\renewenvironment{shaded}{%
    \def\FrameCommand{\fboxsep=\FrameSep \colorbox{shadecolor}}%
    \MakeFramed{\advance\hsize-\width \FrameRestore\FrameRestore}}%
{\endMakeFramed}
\definecolor{shadecolor}{gray}{0.9}

\newenvironment{solution}{%
    \def\FrameCommand{\fboxsep=\FrameSep \colorbox{shadecolor}}%
    \MakeFramed{\advance\hsize-\width \FrameRestore\FrameRestore}
    \textbf{Solution}}%
{\endMakeFramed}

\newcommand{\abs}[1]{\left \lvert #1 \right \rvert}

\definecolor{shadecolor}{gray}{0.9}


\algtext*{EndIf} % Remove "end if" text
\algtext*{EndFor} % Remove "end if" text
\algtext*{EndProcedure} % Remove "end if" text
\algtext*{EndWhile}
\algrenewcommand\algorithmicrequire{\textbf{Input:}} % Input for Procedures
\algrenewcommand\algorithmicensure{\textbf{Output:}} % Output for Procedures

\makeatletter
\newcommand{\algmargin}{\the\ALG@thistlm}
\makeatother
\algnewcommand{\parState}[1]{\State%
    \parbox[t]{\dimexpr\linewidth-\algmargin}{\strut #1\strut}}