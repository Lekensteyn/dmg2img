%define	myrelease		1
%define mybuild			1
%define _rel			%{myrelease}.%{mybuild}

# define the package groups.
# If they all followed the same naming conventions these would be the same.
# They don't, so they probably aren't :(
#
%define	suse_group		Productivity/File utilities
%define	mandriva_group		Productivity/File utilities
%define	fedora_group		Productivity/File utilities

# defaults
#
%define	group			Productivity/File utilities
%define	rel			%{_rel}

%define	my_suse			0
%define	my_mandriva		0
%define	my_fedora		0
%define	my_centos		0


%if 0%{?suse_version:1}%{?sles_version:1}
%define	my_suse			1
%endif

%if 0%{?mandriva_version:1}
%define	my_mandriva		1
%endif

%if 0%{?fedora_version:1}
%define	my_fedora		1
%endif

%if 0%{?centos_version:1}
%define	my_centos		1
%endif


%if %{my_suse}

%if %{suse_version}
%define	rel			%{_rel}.suse%(echo $[%suse_version/10])
%else
%define	rel			%{_rel}.%{sles_version}
%endif

%define	group			%{suse_group}

%endif


# building on a Mandriva/Mandrake Linux system.
#
# this should create a release that conforms to the Mandriva naming conventions.
#
%if %{my_mandriva}

%{?!mkrel:%define mkrel(c:)	%{-c:0.%{-c''}.}%{!?''with''unstable:%(perl -e '$''="%{1}";m/(.\'''\\D\+)?(\\d+)$/;$rel=${2}-1;re;print "$1$rel";').\
%{?subrel:%subrel}%{!?subrel:1}.\
%{?distversion:%distversion}\
%{?!distversion:%(echo $[%{mdkversion}/10])}}\
%{?''with_unstable:%{1}}\
%{?distsuffix:%distsuffix}%{?!distsuffix:mdk}}

%define rel			%mkrel %{_rel}

%define group			%{mandriva_group}

%endif


# building on a Fedora Core Linux system.
#
# this should create a release that conforms to the Fedora naming conventions.
#
%if %{my_fedora}

%if 0%{?!dist:1}
%define	dist			fc%{fedora_version}
%endif

%define	rel			%{myrelease}.%{dist}.%{mybuild}
%define	group			%{fedora_group}

%endif


# building on a CentOS Linux system?
#
# if so, this should create a release that conforms to the CentOS naming conventions.
#
%if 0%{?centos_version:1}>0

%if 0%{?!dist:1}
%define	dist			el%(echo $[%{centos_version}/100])
%endif

%define	my_centos		1
%define	rel			%{myrelease}.%{dist}
%define	group			%{fedora_group}

%endif


%if %{my_suse}

%if %{suse_version}>1020
BuildRequires:			libopenssl-devel
%else

%if %{sles_version}>10
BuildRequires:			libopenssl-devel
%else
BuildRequires:			openssl-devel
%endif

%endif

%endif

%if %{my_mandriva}
BuildRequires:			libopenssl-devel
%endif

%if %{my_fedora}
BuildRequires:			openssl-devel
%endif

%if %{my_centos}
BuildRequires:			openssl-devel
%endif


# Now for the meat of the spec file
#
Name:			dmg2img
Summary:		Converts dmg archives to HFS+ images
Version:		1.6.3
Release:		4.1
Group:			%{group}
License:		GPLv2
Source:			%{name}-%{version}.tar.gz
URL:			http://vu1tur.eu.org/tools/
BuildRoot:		%{_tmppath}/%{name}-%{version}-%{release}-buildroot


%description
DMG2IMG is a tool which allows converting Apple compressed dmg 
archives to standard (hfsplus) image disk files.

This tool handles z-lib compressed dmg images.


%prep
%setup -q


%build
%{__make} CFLAGS="$RPM_OPT_FLAGS"


%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_mandir}/man1
install -m755 %{name} %{buildroot}%{_bindir}/
install -m755 vfdecrypt %{buildroot}%{_bindir}/
install -m644 vfdecrypt.1 %{buildroot}%{_mandir}/man1/


%files
%defattr(-,root,root,0755)
%{_bindir}/%{name}
%{_bindir}/vfdecrypt
%{_mandir}/man1/vfdecrypt.1*
%doc COPYING README


%clean
%{__rm} -rf %{buildroot}
%{__rm} -rf %{_builddir}/%{name}-%{version}-%{release}-buildroot


%changelog
* Thu Sep 25 2008 David Bolt <davjam@davjam.org>
- First spec and build for SUSE.
