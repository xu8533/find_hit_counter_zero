#!C:\Strawberry\perl\bin\perl.exe

use utf8;
use warnings;
use Getopt::Std;
use feature "switch";    # 打开given when结构支持

# use vars qw($opt_c);
# use Getopt::Long qw(:config bundling nopermute noignorecase);
# use Data::Dumper;
use Data::Printer;

# use String::Util qw(trim);
#use strict;
use Spreadsheet::Read;
use Getopt::Long;
use List::Util qw(sum);
use File::Basename qw(basename);

# 输入输出报错支持中文
# use open ":encoding(gbk)", ":std";
binmode( STDOUT, ":encoding(gbk)" );
binmode( STDIN,  ":encoding(gbk)" );
binmode( STDERR, ":encoding(gbk)" );

sub usage {
    my $err = shift and select STDERR;
    print
      "usage: $0 [-n path] [-s file] xxxx.xlsx\n",
      "\t-n path     nat status file directory\n",
      "\t-s file     output file\n";
    exit $err;
}    # 使用方法

my $opt_s;
my $opt_n;

GetOptions(
    "help|?"         => sub { usage(0); },
    "n|nat_status=s" => \$opt_n,
    "s|save=s"       => \$opt_s,

) or usage(1);

if ( $#ARGV < 0 || $#ARGV > 5 ) {
    die
"\nUsage:\tperl hit-counter.pl -n <path to nat status file> <config.xlsx>\n
        Flags:\t-c 保存'show security nat'的目录\n";
}

# 解析"show security nat",找出hit counter为0的rule
sub parseNatStatus {

    my @nat_data_only;
    my @all_data = @_;
    my $star     = "off";

    # my $len = scalar @all_data;
    # print "len is $len\n";
    # my $Nat_type = "static|source|destination";
    # my $Nat_type = ( "static" | "source" | "destination" );
    foreach (@all_data) {

     # 1. 匹配show security nat #Nat_type rule all命令后开始向@nat_data_only存入数据，
     # 2. 匹配"show security nat $Nat_type rule all"以外的命令，停止给@nat_data_only数组添加新数据
     # if ( $star eq "off" && /\bshow security nat $Nat_type rule all\b/ ) {

        if ( $star eq "off"
            && /\bshow security nat (static|source|destination) rule all\b/g )
        {
            $star = "on";

            # print "enter if\n$star\n$_\n\n";
            next;
        }
        elsif (
            $star eq "on"

            # && /\bshow (?!security nat $Nat_type rule all)\b/ )
            && /\bshow (?!security nat (staitc|source|destination) rule all)\b/g
          )
        {
            $star = "off";

            # print "enter elsif\n$star\n$_\n\n";
            next;
        }
        given ($_) {

            # when ( $star eq "on" && /\b$Nat_type NAT rule\:\b/i ) {
            when ( $star eq "on"
                  && /\b(static|source|destination) NAT rule\b/i )
            {
                push @nat_data_only, $_;

                # print "nat rule: $_\n";
                next;
            }
            when ( $star eq "on" && /\bFrom Zone\b/i ) {
                push @nat_data_only, $_;

                # print "from zone: $_\n";
                next;
            }
            when ( $star eq "on" && /\bDestination addresses\b/i ) {
                push @nat_data_only, $_;

                # print "dest addr: $_\n";
                next;
            }
            when ( $star eq "on" && /\bHost addresses\b/i ) {
                push @nat_data_only, $_;

                # print "host addr: $_\n";
                next;
            }
            when ( $star eq "on" && /\bNetmask\b/i ) {
                push @nat_data_only, $_;

                # print "netmask: $_\n";
                next;
            }
            when ( $star eq "on" && /\bTranslation hits\b/i ) {
                push @nat_data_only, $_;

                # print "hit: $_\n";
                next;
            }
            default {
                next;
            }
        }
    }
    return @nat_data_only;
}

# 根据zone，目的地址，nat转换后地址，子网掩码寻找hit和为零的条目，
# 并返回rule name和rule set name
sub find_hit_zero {
    my (
        $find_nat_type,    $find_src_zone, $find_dst_address,
        $find_nat_address, @find_all_nat_text
    ) = @_;

    # print "@find_all_nat_text\n";
    my (
        $rule_name,        $rule_set_name,    $text_from_zone,
        $text_dst_address, $text_nat_address, $text_netmask,
        $text_hit_counter, @hit_counters,     $find_netmask,
        $tmp_rule_name,    $tmp_rule_set_name
    );
    my ( $prefix_find_dst_address, $find_dst_netmask ) =
      split /\//, $find_dst_address;
    my ( $prefix_find_nat_address, $find_nat_netmask ) =
      split /\//, $find_nat_address;

    # print "$find_nat_address\n";
    if ( $find_dst_netmask == $find_nat_netmask ) {
        $find_netmask = $find_dst_netmask;
    }
    else { die "两个子网掩码不相同，请检查"; }

    foreach (@find_all_nat_text) {
        given ($_) {
            when (/\b$find_nat_type nat rule\b/i) {
                ( $tmp_rule_name, $tmp_rule_set_name ) =
                  ( split /\s+/ )[ 3, -1 ];
            }
            when (/\bfrom zone\b/i) {
                $text_from_zone = ( split /\s+/ )[-1];

                # print "txt from zone: $text_from_zone\n";
            }
            when (/\bDestination addresses\b/i) {
                $text_dst_address = ( split /\s+/ )[-1];
            }
            when (/\bhost addresses\b/i) {
                $text_nat_address = ( split /\s+/ )[-1];
            }
            when (/\bnetmask\b/i) { $text_netmask = ( split /\s+/ )[-1]; }
            when (/\btranslation hits\b/i) {
                $text_hit_counter = ( split /\s+/ )[-1];
                if (   ( $text_from_zone eq $find_src_zone )
                    && ( $text_dst_address eq $prefix_find_dst_address )
                    && ( $text_nat_address eq $prefix_find_nat_address )
                    && ( $text_netmask == $find_netmask ) )
                {
                    push @hit_counters, $text_hit_counter;
                    $rule_name     = $tmp_rule_name;
                    $rule_set_name = $tmp_rule_set_name;
                }
            }
        }
    }

    # 对数组求和，和为零时返回rule name和rule-set name
    # print "arrary \@hit_counters is @hit_counters\n";
    my $sum = sum @hit_counters;

    # print "rule name is $rule_name\nrule-set name is $rule_set_name\n";

    # print "sum is $sum\n";
    if ( $sum == 0 ) { return ( $rule_name, $rule_set_name ) }
}

my @commands;     # 保存最终的操作命令
my %nat_files;    # 将文件名和文件内容以hash形式保存

#my $book = ReadData( "$ARGV[0]", parser => "xlsx", "strip" )
my $workbook = Spreadsheet::Read->new( $ARGV[0] )
  or die "无法打开$ARGV[0].";

# my $sheet = $workbook->sheet(1);
my $sheet = $workbook->sheet("sheet1");

# 读取文件夹下的所有文件，并保存到hash中
opendir( DIR, $opt_n ) or die "can't opendir $opt_n $!";
while ( defined( $filename = readdir(DIR) ) ) {
    next if $filename =~ /^\.\.?$/;    # 跳过本级目录和父目录

    # print "$filename\n";
    my $path = "$opt_n\\$filename";
    open my $nat_fh, '<', $path;
    my @orig_data = <$nat_fh>;
    chomp @orig_data;
    close $nat_fh;

    # 获取"show security nat static|source|destination status"输出内容
    my @nat_data_only = parseNatStatus(@orig_data);
    my $filename      = basename( $filename, ".txt" );
    $nat_files{"$filename"} = \@nat_data_only;
}
closedir(DIR);

# print Dumper \%nat_files;
# p %nat_files;

# 读取exel每一行数据，并将其赋值给相关的变量
foreach my $row ( $sheet->{minrow} .. $sheet->{maxrow} ) {
    my @data = $sheet->cellrow($row);
    my ( $nat_type, $hostname, $src_zone, $dst_address, $nat_address ) =
      @data[ 0, 1, 2, 3, 4 ];

    # 删除前导和末尾空白符
    $nat_type    =~ s/^\s+|\s+$//g;
    $hostname    =~ s/^\s+|\s+$//g;
    $src_zone    =~ s/^\s+|\s+$//g;
    $dst_address =~ s/^\s+|\s+$//g;
    $nat_address =~ s/^\s+|\s+$//g;
    given ($nat_type) {

        # print "nat type is $nat_type\n";
        when ( $nat_type =~ /STATIC-NAT/i )      { $nat_type = "static"; }
        when ( $nat_type =~ /SOURCE-NAT/i )      { $nat_type = "source"; }
        when ( $nat_type =~ /DESTINATION-NAT/i ) { $nat_type = "destination"; }
        when ( $nat_type =~ /DNAT/i )            { $nat_type = "destination"; }
        default {
            print "未找到NAT类型，请检查相关条目...\n$_\n";
        }
    }

    # 获取rule name和rule set name
    if ( exists( $nat_files{$hostname} ) ) {
        my ( $real_rule_name, $real_rule_set_name ) =
          find_hit_zero( $nat_type, $src_zone, $dst_address, $nat_address,
            @{ $nat_files{"$hostname"} } )
          if length( $nat_type && $dst_address && $nat_address );

        # 输出hit counter为0的文件名和删除命令
        push @commands,
            "$hostname: delete security "
          . "nat $nat_type rule-set $real_rule_set_name "
          . "rule $real_rule_name\n"
          if defined( $real_rule_set_name && $real_rule_name );
    }
    else { print "$hostname 文件不存在，请检查...\n"; }
}

END {
    # 去重并排序
    my @removed_duplicate_commands = do {
        my %tmp_command;
        grep { !$tmp{$_}++ } @commands;
    };
    print sort @removed_duplicate_commands;
}
