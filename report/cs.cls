\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{cs}[2003/06/15 v3.0 (dnr)]
\LoadClass[11pt]{article}
\RequirePackage[margin=72pt]{geometry} % This line sets the page to use 1 inch margins - andrew 2010.05.15
\RequirePackage{amsmath}
%\RequirePackage{psfig}
\RequirePackage{ifthen}
\RequirePackage{verbatim} % has the "comment" environment
\RequirePackage{import}
\RequirePackage{hyperref}
%
% Not designed to stand alone; class that loads this one should
% declare the robust commands \CS@classnum, \CS@classname, and
% \CS@prof _before_ loading this. also declare \CS@probdir with \def.
%
% A document which uses this class should call \docdate{} with the 
% date the whatever will be out or due, and one of \hwk{}, \pset{}, \proj{},
% \quiz{}, \lab{}, \notes{} or \exam{}, each with a number specifying
% which one it is (i.e. "homework 1" would be \hwk{1}), or \misc{}, with
% the title of the handout (e.g. \misc{Course Missive}).
%
% The \makesolutions command, in the header, indicates that the doc is a
% solution key; it changes the headers slightly. The \draft command in
% the header indicates that the doc is a draft, and will somehow affect
% the printed document.  An optional argument to \draft will be printed
% in some suitably conspicuous place.
%
% Homeworks should then go on to call \prob{} with the name of the file
% which contains each problem, sans .tex extension (i.e. \prob{a2} for a
% problem which is in a2.tex).
%
% -------------------------------------------------------------
%
% first, decide what type of document it is, and define appropriate
% variables and macros
\newboolean{CS@hascoverpage}
\setboolean{CS@hascoverpage}{false}
\newboolean{CS@separatepages}
\setboolean{CS@separatepages}{false}
\newboolean{CS@hasspecialdate}
\setboolean{CS@hasspecialdate}{false}
\newboolean{CS@issubt}
\setboolean{CS@issubt}{false}
\newboolean{CS@issol}
\setboolean{CS@issol}{false}
\newboolean{CS@isdraft}
\setboolean{CS@isdraft}{false}
\newboolean{CS@islab}
\setboolean{CS@islab}{false}
\newboolean{CS@ishwkorlab}
\setboolean{CS@ishwkorlab}{false}
\newboolean{CS@isproj}
\setboolean{CS@isproj}{false}
\newboolean{CS@isquiz}
\setboolean{CS@isquiz}{false}
\newboolean{CS@isexam}
\setboolean{CS@isexam}{false}
\newboolean{CS@ismisc}
\setboolean{CS@ismisc}{false}
\DeclareRobustCommand{\CS@asgnname}{Assignment}
\newboolean{CS@isprac}
\setboolean{CS@isprac}{false}
\newcommand{\inputprobfile}[1]{
  % this has a lot of cases, because we have to support two conventions.
  % for non-solutions: we search #1.tex, $PRODIR/#1/prob.tex, then
  % $PROBDIR/#1/#1.tex
  % for solutions, search: #1.sol.tex, $PROBDIR/#1/prob.tex, then
  % $PROBDIR/#1/#1.tex
  \ifthenelse{\boolean{CS@issol}}
  {\IfFileExists{#1.sol.tex}
    {
    \input{#1.tex}
    \subsection*{Solution}
    \input{#1.sol.tex}
    }
   {
   \IfFileExists{#1.tex}
    {
    \input{#1.tex}
    \subsection*{No Solution Available}
    }
    {\IfFileExists{\CS@probdir/#1/prob.tex}
     {\import{\CS@probdir/#1/}{prob.tex}}
     {\IfFileExists{\CS@probdir/#1/#1.tex}
      {\import{\CS@probdir/#1/}{#1.tex}}
      {\typeout{*** Warning: Can't locate problem "#1" on search path.}
       \stop}}}}}
  {\IfFileExists{#1.tex}
   {\input{#1.tex}}
   {\IfFileExists{\CS@probdir/#1/prob.tex}
    {\import{\CS@probdir/#1/}{prob.tex}}
    {\IfFileExists{\CS@probdir/#1/#1.tex}
     {\import{\CS@probdir/#1/}{#1.tex}}
     {\typeout{*** Warning: Can't locate problem "#1" on search path.}
      \stop}}}}
}
\newcommand*{\hwk}[1]{ %
  \DeclareRobustCommand{\CS@asgnname}{Homework #1} %
  \setboolean{CS@ishwkorlab}{true} %
  \DeclareRobustCommand{\CS@asgnnum}{#1} %
  \DeclareRobustCommand{\CS@dateprefix}{Due: } %
  \setboolean{CS@isprac}{false} %
}

\newcommand*{\mdtrm}[1]{ %
  \DeclareRobustCommand{\CS@asgnname}{Midterm #1} %
  \setboolean{CS@ishwkorlab}{true} %
  \DeclareRobustCommand{\CS@asgnnum}{#1} %
  \DeclareRobustCommand{\CS@dateprefix}{Due: } %
  \setboolean{CS@isprac}{false} %
}

\newcommand*{\rec}[1]{ %
  \DeclareRobustCommand{\CS@asgnname}{Recitation #1}%
  \setboolean{CS@ishwkorlab}{true}%
  \DeclareRobustCommand{\CS@asgnnum}{#1} %
  \DeclareRobustCommand{\CS@dateprefix}{} %
  \setboolean{CS@isprac}{true} %
}

\newcommand*{\pset}[1]{ %
  \DeclareRobustCommand{\CS@asgnname}{Problem Set #1} %
  \setboolean{CS@ishwkorlab}{true} %
  \DeclareRobustCommand{\CS@asgnnum}{#1} %
  \DeclareRobustCommand{\CS@dateprefix}{Due: } %
  \setboolean{CS@isprac}{false} %
}
\newcommand*{\prob}[2][points]{
  \ifthenelse{\equal{#1}{points}}
  {\DeclareRobustCommand{\CS@pointcount}{}}
  {\DeclareRobustCommand{\CS@pointcount}{\small (#1 pts.)}}
  \ifthenelse{\boolean{CS@isexam}}
  {
      \ifthenelse{\boolean{CS@separatepages}}
      {\pagebreak}
      {}
      \subsection{\CS@pointcount}
      \inputprobfile{#2}
  }
  {
    \ifthenelse{\boolean{CS@isquiz}}
    {
      \ifthenelse{\value{subsection} > 0}
      {\vspace{1in}}
      {}
      \subsection{\CS@pointcount}
    }
    {
      \ifthenelse{\boolean{CS@isprac}} %
        {\section*{Problems} \setboolean{CS@isprac}{false}} %
        {} %
      \subsection{\CS@pointcount} %
      \inputprobfile{#2}
    }
  }
}
\DeclareRobustCommand{\asgnnum}[1]{\DeclareRobustCommand{\CS@asgnnum}{#1}}
\newcommand*{\prac}[1]{
  \section*{Practice} %
  \inputprobfile{#1}
  \setboolean{CS@isprac}{true} %
}
\newcommand*{\misc}[1]{
  \DeclareRobustCommand{\CS@asgnname}{#1}%
  \DeclareRobustCommand{\CS@asgnnum}{}%
  \DeclareRobustCommand{\CS@dateprefix}{}%
}
\newcommand*{\quiz}[1]{
  \DeclareRobustCommand{\CS@asgnname}{Quiz #1}%
  \DeclareRobustCommand{\CS@asgnnum}{#1}%
  \DeclareRobustCommand{\CS@dateprefix}{}%
  \setboolean{CS@isquiz}{true}
}
\newcommand*{\lab}[1]{ %
  \DeclareRobustCommand{\CS@asgnname}{Lab #1}%
  \setboolean{CS@ishwkorlab}{true} %
  \setboolean{CS@islab}{true} %
  \DeclareRobustCommand{\CS@asgnnum}{#1} %
  \DeclareRobustCommand{\CS@dateprefix}{Out: } %
  \newcommand{\intro}{\textbf{Introduction} \\}
  \newcommand{\task}{\textbf{Task:} }
  \newcommand{\stestaps}{\textbf{Steps:} }
}
\newcommand*{\proj}[1]{ %
  \DeclareRobustCommand{\CS@asgnname}{Project #1} %
  \DeclareRobustCommand{\CS@asgnnum}{#1} %
  \DeclareRobustCommand{\CS@dateprefix}{Due: } %
  \setboolean{CS@isproj}{true} %
}
\newcommand*{\notes}[1]{ %
  \DeclareRobustCommand{\CS@asgnname}{Lecture #1 Notes} %
  \DeclareRobustCommand{\CS@asgnnum}{#1} %
  \DeclareRobustCommand{\CS@dateprefix}{} %
}
\newcommand*{\exam}[1]{ %
  \DeclareRobustCommand{\CS@asgnname}{Exam #1} %
  \DeclareRobustCommand{\CS@asgnnum}{#1} %
  %\DeclareRobustCommand{\CS@dateprefix}{} %
  \DeclareRobustCommand{\CS@dateprefix}{Due: } %
  \setboolean{CS@isexam}{true}
  \renewcommand{\labelenumi}{\alph{enumi}.}
}
\newcommand*{\separatepages}{
  \setboolean{CS@separatepages}{true}
}
\newcommand{\coverpage}[1]{
  \setboolean{CS@hascoverpage}{true}
  \DeclareRobustCommand{\CS@coverpage}{#1}
}
\newcommand*{\sol}{
  \setboolean{CS@issol}{true}
}
% the new way to set issol to be true. \sol in the preamble is
% deprecated.
\newcommand*{\makesolutions}{
  \setboolean{CS@issol}{true}
}
\DeclareRobustCommand{\Mon}{\ifcase\month\or
        Jan\or Feb\or Mar\or Apr\or May\or Jun\or
        Jul\or Aug\or Sep\or Oct\or Nov\or Dec\fi}
\newcommand*{\draft}[1][DRAFT]{  %argument is now ignored
  \setboolean{CS@isdraft}{true}
  \DeclareRobustCommand{\CS@draftid}{\number\year\Mon\number\day-\PrintTime}
  \newsavebox{\CS@drafthead}
  \savebox{\CS@drafthead}[\textwidth]
  {\Large\bf\em DRAFT \hfill ---
              \hfill \CS@draftid \hfill --- \hfill DRAFT}
  \newlength{\CS@draftheight}
%  \newlength{\CS@tempheight}
%  \settoheight{\CS@draftheight}{\usebox{\CS@drafthead}}
%  \settodepth{\CS@tempheight}{\usebox{\CS@drafthead}}
%  \addtolength{\CS@draftheight}{\CS@tempheight}
  \setlength{\CS@draftheight}{3.8ex}
}
\newcommand*{\specialdate}[1]{
  \setboolean{CS@hasspecialdate}{true}
  \DeclareRobustCommand{\CS@specialdate}{#1}
}
\newcommand*{\subtitle}[1]{
  \setboolean{CS@issubt}{true}
  \DeclareRobustCommand{\CS@subtitle}{#1}
}
%
% now, set up the page styles (one for first page, one for subsequent
% pages)
\newlength{\CS@classnumwidth}
\settowidth{\CS@classnumwidth}{\CS@classnum}
\DeclareRobustCommand{\CS@duedate}{\scshape tba}
\newcommand*{\docdate}[1]{\DeclareRobustCommand{\CS@duedate}{#1}}
\newcommand*{\due}{\docdate}

\DeclareRobustCommand{\gradingtable}[1]{
{
\newcounter{val}
\setcounter{val}{#1}

\Large
\newcounter{cur}
\setlength{\unitlength}{15.6pt}
\begin{picture}(0,\value{val})
\setlength{\unitlength}{15pt}
\multiput(0,\value{val})(0,-1){\value{val}}{\framebox(1,1){\stepcounter{cur}\arabic{cur}}}
\multiput(1,\value{val})(0,-1){\value{val}}{\framebox(3,1){}}
\put(0,-1.2){\framebox(1,2){T}}
\put(1,-1.2){\framebox(3,2){}}

\newsavebox{\temp}
\setlength{\unitlength}{15.2pt}
\savebox{\temp}(0,0)[bl]{
\put(-.2,0){\line(0,1){\value{val}}}
\put(4.2,0){\line(0,1){\value{val}}}
\put(-.2,\value{val}){\line(1,0){4.4}}
\put(-.2,0){\line(0,-1){2.4}}
\put(4.2,0){\line(0,-1){2.4}}
\put(-.2,-2.4){\line(1,0){4.4}}
}
\put(0,-1.4){\usebox{\temp}}
\end{picture}
}
}
\newcommand{\ps@firsthead}{ %
  \renewcommand{\@oddhead}{ %
    \CS@classnum\hfill %
    \CS@classname\hfill %
    \makebox[\CS@classnumwidth][r]{\CS@prof} %
  } %
  \renewcommand{\@oddfoot}{} %
  \renewcommand{\@evenhead}{\@oddhead} %
  \renewcommand{\@evenfoot}{\@oddfoot} %
}
\newcommand{\ps@head}{ %
  \renewcommand{\@oddhead}{ %
    \ifthenelse{\boolean{CS@isdraft}}
    {{\em DRAFT\CS@draftid}}
    {\CS@classnum}
    \hfill %
    \CS@asgnname\hfill %
    \ifthenelse{\boolean{CS@issol}}
    {\makebox[\CS@classnumwidth][r]{\textbf{Solution Key}}} %
    {\makebox[\CS@classnumwidth][r]{\textbf{\CS@duedate}}} %
} 
  \renewcommand{\@oddfoot}{\hfill \thepage \hfill} %
  \renewcommand{\@evenhead}{\@oddhead} %
  \renewcommand{\@evenfoot}{\@oddfoot} %
}
\pagestyle{head}
\thispagestyle{firsthead}
\newenvironment{blockindent}{\begin{list}{\quad}{}}{\end{list}}
%
% finally, display the header for the front page
\AtBeginDocument{
  \begin{center}
  {\huge \bf \CS@asgnname}\\ %
  \ifthenelse{\boolean{CS@issubt}} %
    {{\LARGE \bf \CS@subtitle \\ }} %
    {} %
  \ifthenelse{\boolean{CS@issol}}
    {\Large \bf\vspace{1ex} Solution Key}
    {\ifthenelse{\boolean{CS@hasspecialdate}}
%      {\Large \em\vspace{1ex}\CS@specialdate}
%      {\Large \em\vspace{1ex}\CS@dateprefix\CS@duedate}
      {\Large \vspace{1ex}\CS@specialdate}
      {\Large \vspace{1ex}\CS@dateprefix\CS@duedate}
    }
  \ifthenelse{\boolean{CS@isdraft}} %
    {\usebox{\CS@drafthead}\vspace{-\CS@draftheight}}
%    {   \setlength{\unitlength}{1in} %
%       \begin{picture}(0,0)(2,.2) %
%         \put(0,0){
%           \makebox(5,0){\Large\bf\em DRAFT \hfill ---
%             \hfill \CS@draftid \hfill --- \hfill DRAFT} 
%         } %
%       \end{picture} %
%    } %
    {} %
  \end{center}
  \ifthenelse{\boolean{CS@hascoverpage}}
  {\CS@coverpage\newpage\vspace*{3in}\newpage}
  {}

  % dnr, june 15 2003
  \ifthenelse{\boolean{CS@issol}} % if we're doing solutions
   {% define a sol environment that makes text normal
    \let\sol\rm\let\endsol\relax
   }
   % otherwise, make the sol environment act like comment
   {\let\sol\comment\let\endsol\endcomment}
  % oh, and ignore anything in the meta environment
  \let\meta\comment
  \let\endmeta\endcomment
}

% grab packages from our problems.
%
% this clever but revolting hack solves several problems at once. we
% need to grep through all the problem files to find their (commented
% out) \usepackage{} lines and then execute them right now. tex provides
% a way to escape to the shell with \write18, but we have to send the
% output to a file and then \input it if we want it to get interpreted.
% latex doesn't deal with such reasonable characters as backslashes in
% the contents of a \write18, so we base64 encode the script and run it
% indirectly. the script needs to know the values of some tex variables,
% so we pass those in as environment variables, using env (a little more
% robust than positional paramters).
%
% the other problem we have is that we'd like to set the value of
% \CS@issol based on the environment variable MAKESOLUTIONS. tex has no
% getenv, so we let the script test for the variable, and output a
% \makesolutions command (defined above) if it's true.
%
% to edit the "script", pipe it through mmencode -u, then pipe it
% through mmencode when you're done.
%
% dnr, june 15 2003
\immediate\write18{echo
ZWNobyAxPiYyCmVjaG8gIlNjYW5uaW5nIGZvciBcXHVzZXBhY2thZ2UgZGVjbGFyYXRpb25z
IGluIHByb2JsZW0gZmlsZXM6IiAxPiYyCmQ9IiRKT0JOQU1FLnRleCIKZWNobyAiRm91bmQg
ZG9jdW1lbnQ6ICRkIiAxPiYyCmZvciBwIGluIGBzZWQgLW5lICcvXFxcXHByW29hXVtiY11c
XD4vcy8uKntcXCguKlxcKX0uKi9cXDEvcCcgIiRkImA7IGRvCgllY2hvICJGb3VuZCBwcm9i
bGVtOiAkcCIgMT4mMgoJc2VkIC1uZSAncy8uKlwoXFx1c2VwYWNrYWdley4qfVwpLiovXDEv
cCcgIiRQUk9CRElSLyRwIi8qLnRleApkb25lCiMgdXVnaCwgdGhpcyBzaG91bGRuJ3QgYmUg
aGVyZToKWyAiJE1BS0VTT0xVVElPTlMiIF0gJiYgZWNobyBcXG1ha2Vzb2x1dGlvbnMK
| mmencode -u | env 'JOBNAME=\jobname' 'PROBDIR=\CS@probdir' sh > packages.tmp}
\IfFileExists{packages.tmp}
{\input{packages.tmp} \immediate\write18{rm -f packages.tmp}}
{\typeout{*** Warning: Can't extract \\usepackage declarations from problem files.}
 \typeout{*** Did you forget to run with -shell-escape?}}

