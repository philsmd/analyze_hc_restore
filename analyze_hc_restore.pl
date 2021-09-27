#!/usr/bin/env perl

# Author: philsmd
# License: public domain
# First released: January 2015
# Last updated: September 2021

use strict;
use warnings;

#
# Constants
#

my $FILE_SIZE_MIN = 4 + 256 + 4 + 4 + 8 + 4;

#
# Helper functions
#

sub usage
{
  my $script_name = shift;

  print "Usage: $script_name [OPTIONS] RESTORE_FILE.restore\n\n";

  print "where [OPTIONS] can be:\n";
  print "$script_name specific OPTIONS:\n";
  print "-h | --help                      Show this usage\n";
  print "-f | --file FILE                 Set the output file. Specify the file where this script should write to if some options are being modified\n";
  print "-Q | --quiet-mode                Print only what is necessary, don't print .restore file info etc\n";

  print "\ngeneral OPTIONS for the .restore file:\n";
  print "-V | --version NUM               Set the hashcat version to NUM\n";
  print "-C | --cwd PATH                  Set the working directory to PATH\n";
  print "-D | --dictpos NUM               Set the number of dictionary to NUM. This is the current position if there are more than one dict\n";
  print "-M | --maskpos NUM               Set the current position within the .hcmask file to NUM\n";
  print "-P | --pw_cur  NUM               Set the current password value/position to NUM\n";
  print "-L | --line STRING               Set the whole command line to STRING\n";

  print "\nOPTIONS for the command-line\n";
  print "-q | --quiet                     Set the --quiet command line switch\n";
  print "-s | --status                    Set the --status command line switch\n";
  print "-A | --status-automat            Set the --status-automat command line switch\n";
  print "-H | --outfile-autohex-disable   Set the --outfile-autohex-disable command line switch\n";
  print "-v | --remove                    Set the --remove command line switch\n";
  print "-p | --potfile-disable           Set the --potfile-disable command line switch\n";
  print "-G | --logfile-disable           Set the --logfile-disable command line switch\n";
  print "-T | --gpu-temp-disable          Set the --gpu-temp-disable command line switch\n";
  print "-i | --increment                 Set the --increment command line switch\n";
  print "-t | --runtime NUM               Set the --runtime to NUM seconds\n";
  print "-E | --session VALUE             Set the --session name to VALUE\n";
  print "-o | --outfile VALUE             Set the --outfile to the path specified by VALUE\n";
  print "-F | --outfile-format NUM        Set the --outfile-format to the value specified by NUM\n";
  print "-U | --status-timer NUM          Set the --status-timer to NUM seconds\n";
  print "-e | --outfile-check-timer NUM   Set the --outfile-check-timer to NUM seconds\n";
  print "-I | --remove-timer NUM          Set the --remove-timer to NUM seconds\n";
  print "-b | --debug-mode NUM            Set the --debug-mode to NUM\n";
  print "-B | --debug-file VALUE          Set the --debug-file to the path specified by VALUE\n";
  print "-N | --induction-dir VALUE       Set the --induction-dir to the folder specified by VALUE\n";
  print "-K | --outfile-check-dir VALUE   Set the --outfile-check-dir to the folder specified by VALUE\n";
  print "-c | --segment-size NUM          Set the --segment-size to NUM\n";
  print "-d | --gpu-devices VALUE         Set the --gpu-devices to the comma-separated list given by VALUE\n";
  print "-O | --optimized-kernel-enable   Set the --optimized-kernel-enable command line switch\n";
  print "-w | --workload-profile NUM      Set the workload profile to NUM; select between the performance profiles 1 (reduced), 2 (default) or 3 (tuned)\n";
  print "-n | --kernel-accel NUM          Set the --kernel-accel (outerloop step size) to NUM. 1, 8, 40, 80, 160\n";
  print "-u | --kernel-loops NUM          Set the --kernel-loops (innerloop step size) to NUM. 8 - 1024\n";
  print "-R | --force                     Set the --force command line switch (REQUIRED if electing to use -n -u params over the officially recommended '-w' option\n";
  print "-a | --gpu-temp-abort NUM        Set the --gpu-temp-abort to NUM degrees\n";
  print "-m | --gpu-temp-retain NUM       Set the --gpu-temp-retain to NUM degrees\n";
  print "-y | --scrypt-tmto NUM           Set the time/memory trade-off value --scrypt-tmto to NUM (for scrypt only)\n";
  print "-j | --rule-left VALUE           Set the --rule-left value to VALUE\n";
  print "-k | --rule-right VALUE          Set the --rule-right value to VALUE\n";
  print "-r | --rules-file VALUE          Set the --rules-file to VALUE\n";
  print "-g | --generate-rules VALUE      Set the --generate-rules value to VALUE\n";
  print "-1 | --custom-charset1 VALUE     Set the --custom-charset1 to VALUE\n";
  print "-2 | --custom-charset2 VALUE     Set the --custom-charset2 to VALUE\n";
  print "-3 | --custom-charset3 VALUE     Set the --custom-charset3 to VALUE\n";
  print "-4 | --custom-charset4 VALUE     Set the --custom-charset4 to VALUE\n";
  print "-x | --increment-min NUM         Set the --increment-min to NUM\n";
  print "-Y | --increment-max NUM         Set the --increment-max to NUM\n";
  print "-S | --set option=VALUE          Add a list of specific hashcat options [option] to the values indicated by [VALUE]. This list is comma-separated\n";
  print "-R | --rem option[=VALUE]        Remove specific switch(es) or parameter(s) from the command line. This list is comma-separated\n";
}

sub print_file_content
{
  my $file_name = shift;
  my $file_contents = shift;

  my %contents = %$file_contents;

  my $full_arguments = $contents{'argv'};

  $full_arguments =~ s/\n/ /g;

  my $version = sprintf ("%.02f", ($contents{'version'} / 100));

  print "hashcat .restore file: $file_name"                . "\n";
  print "  hashcat version....: " . $version               . "\n";
  print "  working directory..: " . $contents{'cwd'}       . "\n";
  print "  dictionary number..: " . $contents{'dicts_pos'} . "\n";
  print "  mask number........: " . $contents{'masks_pos'} . "\n";
  print "  current password...: " . $contents{'words_cur'} . "\n";
  print "  number of arguments: " . $contents{'argc'}      . "\n";
  print "  full arguments.....: " . $full_arguments        . "\n";
}

sub analyze_file
{
  my $file = shift;
  my $quiet_mode = shift;

  if (! open (FP, "<$file"))
  {
    print "ERROR: could not open .restore file '$file'\n";

    exit (1);
  }

  binmode (FP);

  # Read file

  my $file_size = -s $file;

  if ($file_size < $FILE_SIZE_MIN)
  {
    print "ERROR: file size is too small for a complete .restore file\n";

    exit (1);
  }

  # version number

  my $version_num = 0;

  if (read (FP, $version_num, 4) != 4)
  {
    print "ERROR: could not read the version information\n";

    exit (1);
  }

  $version_num = unpack ("L*", $version_num);

  # cwd

  my $current_working_directory = "";

  if (read (FP, $current_working_directory, 256) != 256)
  {
    print "ERROR: could not read the current working directory\n";

    exit (1);
  }

  # dicts_pos

  my $dictionary_pos = 0;

  if (read (FP, $dictionary_pos, 4) != 4)
  {
    print "ERROR: could not read the number of dictionaries that was last processed\n";

    exit (1);
  }

  $dictionary_pos = unpack ("L*", $dictionary_pos);

  # masks_pos

  my $masks_pos = 0;

  if (read (FP, $masks_pos, 4) != 4)
  {
    print "ERROR: could not read the .hcmask file position\n";

    exit (1);
  }

  $masks_pos = unpack ("L*", $masks_pos);

  # skip (alignment)

  my $skipped = "";

  if (read (FP, $skipped, 4) != 4)
  {
    print "ERROR: could not skip 4 bytes\n";

    exit (1);
  }

  # words_cur

  my $words_cur = 0;

  if (read (FP, $words_cur, 8) != 8)
  {
    print "ERROR: could not read the 'password current' value\n";

    exit (1);
  }

  $words_cur = unpack ("Q*", $words_cur);

  # argc

  my $argc = 0;

  if (read (FP, $argc, 4) != 4)
  {
    print "ERROR: could not read the argument count\n";

    exit (1);
  }

  $argc = unpack ("L*", $argc);

  # skip (alignment)

  if (read (FP, $skipped, 4) != 4)
  {
    print "ERROR: could not skip 4 bytes\n";

    exit (1);
  }

  # argv pointer

  my $argv_ptr;

  if (read (FP, $argv_ptr, 8) != 8)
  {
    print "ERROR: could not read the argument list (argv)\n";

    exit (1);
  }

  # argv

  my $argv = "";

  if (read (FP, $argv, 4096) < 1)
  {
    print "ERROR: could not read the command line string\n";

    exit (1);
  }

  close (FP);

  # copy data to %file_contents

  my %file_contents =
  (
    'version'   => $version_num,
    'cwd'       => $current_working_directory,
    'dicts_pos' => $dictionary_pos,
    'masks_pos' => $masks_pos,
    'words_cur' => $words_cur,
    'argc'      => $argc,
    'argv_ptr'  => $argv_ptr,
    'argv'      => $argv
  );

  # print content if quiet_mode is not enabled

  if ($quiet_mode == 0)
  {
    print_file_content ($file, \%file_contents);
  }

  return %file_contents;
}

sub write_modified_file
{
  my $file = shift;
  my $file_contents = shift;

  if (! open (FP, ">$file"))
  {
    print "ERROR: could not open .restore file '$file'\n";

    exit (1);
  }

  binmode (FP);

  # write $file_contents to file

  my %contents = %$file_contents;

  # version number

  print FP pack ("L*", $contents{'version'});

  # current working directory (must be always exactly 256 chars long)

  print FP $contents{'cwd'} . ("\x00" x (256 - length ($contents{'cwd'})));

  # current dictionary

  print FP pack ("L*", $contents{'dicts_pos'});

  # current mask number

  print FP pack ("L*", $contents{'masks_pos'});

  # skipped (alignment)

  print FP "\x00" x 4;

  # password current

  print FP pack ("Q*", $contents{'words_cur'});

  # argument count

  print FP pack ("L*", $contents{'argc'});

  # skipped (alignment)

  print FP "\x00" x 4;

  # argv pointer

  print FP $contents{'argv_ptr'};

  # argv

  print FP $contents{'argv'};

  close (FP);
}

sub split_cmd_line
{
  my $cmd_line = shift;

  my $cmd_length = length ($cmd_line);

  my $is_open_quote = 0;
  my $quote_char = "";

  my $line = "";
  my $prev_char = "";

  for (my $i = 0; $i < $cmd_length; $i++)
  {
    my $char = substr ($cmd_line, $i, 1);

    if ($is_open_quote == 0)
    {
      if ($char eq " ")
      {
        if ($prev_char ne " ")
        {
          $line .= "\n";
        }
      }
      else
      {
        if (($char eq '"') || ($char eq "'"))
        {
          $is_open_quote = 1;
          $quote_char = $char;
        }

        $line .= $char;
      }
    }
    else
    {
      if ($char eq $quote_char)
      {
        $is_open_quote = 0;
      }

      $line .= $char;
    }

    $prev_char = $char;
  }

  # always add a newline to the end

  $line .= "\n";

  return $line;
}

sub split_on_commas
{
  my $parameter_list = shift;

  my @ret = ();

  my $length = length ($parameter_list);

  my $prev_char = "";

  my $offset = 0;

  for (my $i = 0; $i < $length; $i++)
  {
    my $char = substr ($parameter_list, $i, 1);

    if ($char eq ",")
    {
      if ($prev_char ne "\\")
      {
        my $str = substr ($parameter_list, $offset, $i - $offset);
        $str =~ s/\\,/,/g;

        push (@ret, $str);

        $offset = $i + 1;
      }
    }

    $prev_char = $char;
  }

  if ($offset < $length)
  {
    my $str = substr ($parameter_list, $offset);
    $str =~ s/\\,/,/g;

    push (@ret, $str);
  }

  return @ret;
}

sub split_on_first_equal_sign
{
  my $option = shift;

  my @ret = ();

  my $length = length ($option);

  my $offset = 0;

  for (my $i = 0; $i < $length; $i++)
  {
    my $char = substr ($option, $i, 1);

    if ($char eq "=")
    {
      $offset = $i;

      last;
    }
  }

  if ($offset > 0)
  {
    @ret = (substr ($option, 0, $offset), substr ($option, $offset + 1));
  }
  else
  {
    @ret = ($option);
  }

  return @ret;
}

sub is_already_in_cmd_line
{
  my $argv = shift;
  my $switch = shift;

  my $option = "";
  my $offset = 0;

  my $length = length ($argv);

  for (my $i = 0; $i < $length; $i++)
  {
    my $char = substr ($argv, $i, 1);

    if ($char eq "\n")
    {
      $option = substr ($argv, $offset, $i - $offset);

      if ($option eq $switch)
      {
        return 1;
      }

      $offset = $i + 1;
    }
  }

  return 0;
}

sub add_to_beginning
{
  my $file_info = shift;
  my $switch = shift;
  my $number_args = shift;

  $file_info->{'argc'} += $number_args;

  $file_info->{'argv'} =~ s/\n/\n$switch\n/; # no /g options, hence we change only the first one
}

sub add_cmd_line_switch
{
  my $file_info = shift;
  my $switch = shift;

  my %info = %$file_info;

  # check if already present

  if (is_already_in_cmd_line ($info{'argv'}, $switch))
  {
    print "\nWARNING: the switch '$switch' is already present in the command line. Will be skipped\n";
  }
  else
  {
    add_to_beginning ($file_info, $switch, 1);
  }
}

sub add_cmd_line_param
{
  my $file_info = shift;
  my $param_options = shift;
  my $param_value = shift;

  my $length = length ($file_info->{'argv'});

  my @search_params = @$param_options;

  if (scalar (@search_params) < 1)
  {
    return;
  }

  # add quotes if needed

  if ($param_value =~ m/ /)
  {
    $param_value = "\"$param_value\"";
  }

  # try to find if parameter is already present

  my $option = "";
  my $offset = 0;
  my $found  = "";

  for (my $i = 0; $i < $length; $i++)
  {
    my $char = substr ($file_info->{'argv'}, $i, 1);

    if ($char eq "\n")
    {
      $option = substr ($file_info->{'argv'}, $offset, $i - $offset);

      if ($found ne "")
      {
        my $option_length = length ($option);
        my $option_start  = $offset;

        substr ($file_info->{'argv'}, $option_start, $option_length) = $param_value;

        last;
      }

      foreach my $param (@search_params)
      {
        if ($option eq $param)
        {
          $found = $option;
        }
      }

      $offset = $i + 1;
    }
  }

  # if not found, just add it

  if ($found eq "")
  {
    add_to_beginning ($file_info, "$search_params[0]\n$param_value", 2)
  }
}

sub rem_cmd_line_param
{
  my $file_info = shift;
  my $param_option = shift;
  my $param_value = shift;

  my $length = length ($file_info->{'argv'});

  # try to find if parameter is present

  my $option = "";
  my $offset = 0;
  my $start  = 0;
  my $end    = 0;
  my $found  = "";

  for (my $i = 0; $i < $length; $i++)
  {
    my $char = substr ($file_info->{'argv'}, $i, 1);

    if ($char eq "\n")
    {
      $option = substr ($file_info->{'argv'}, $offset, $i - $offset);

      if ($found ne "")
      {
        if ($option eq $param_value)
        {
          $start = $offset - length ($param_option) - 1;
          $end   = $offset + length ($option) + 1;

          last;
        }
        else
        {
          $found = "";
        }
      }

      if ($option eq $param_option)
      {
        $found = $option;
      }
      else
      {
      }

      $offset = $i + 1;
    }
  }

  if ($found ne "")
  {
    substr ($file_info->{'argv'}, $start, $end - $start) = "";

    $file_info->{'argc'} -= 2;
  }
  else
  {
    print "\nWARNING: command line parameter '$param_option $param_value' not found. Will be skipped\n";
  }
}

sub rem_cmd_line_switch
{
  my $file_info = shift;
  my $switch = shift;

  my $length = length ($file_info->{'argv'});

  # try to find if the switch is present

  my $option = "";
  my $offset = 0;
  my $start  = 0;
  my $end    = 0;
  my $found  = "";

  for (my $i = 0; $i < $length; $i++)
  {
    my $char = substr ($file_info->{'argv'}, $i, 1);

    if ($char eq "\n")
    {
      $option = substr ($file_info->{'argv'}, $offset, $i - $offset);

      if ($option eq $switch)
      {
        $found = $option;

        $start = $offset;
        $end   = $offset + length ($option) + 1;

        last;
      }

      $offset = $i + 1;
    }
  }

  if ($found ne "")
  {
    substr ($file_info->{'argv'}, $start, $end - $start) = "";

    $file_info->{'argc'}--;
  }
  else
  {
    print "\nWARNING: command line switch '$switch' not found. Will be skipped\n";
  }
}

#
# START
#

my $script_name = $0;

if (scalar (@ARGV) < 1)
{
  print "ERROR: please specify the .restore file as command line argument\n\n";

  usage ($script_name);

  exit (1);
}

my $switch = "";

my $quiet_mode = 0;
my $input_file = "";
my $output_file = "";

my $version = "";
my $cwd = "";
my $dicts_pos = "";
my $masks_pos = "";
my $words_cur = "";
my $cmd_line = "";

my $quiet = "";
my $status = "";
my $status_automat = "";
my $outfile_autohex_disable = "";
my $remove = "";
my $potfile_disable = "";
my $logfile_disable = "";
my $gpu_temp_disable = "";
my $increment = "";
my $optimized_kernel = "";

my $runtime_param = "";
my $session_param = "";
my $outfile_param = "";
my $outfile_format_param = "";
my $status_timer_param = "";
my $outfile_check_timer_param = "";
my $remove_timer_param = "";
my $debug_mode_param = "";
my $debug_file_param = "";
my $induction_dir_param = "";
my $outfile_check_dir_param = "";
my $segment_size_param = "";
my $gpu_devices_param = "";
my $workload_profile_param = "";
my $gpu_accel_param = "";
my $gpu_loops_param = "";
my $gpu_force = "";
my $gpu_temp_abort_param = "";
my $gpu_temp_retain_param = "";
my $scrypt_tmto_param = "";
my $rule_left_param = "";
my $rule_right_param = "";
my $rules_file_param = "";
my $generate_rules_param = "";
my $custom_charset1_param = "";
my $custom_charset2_param = "";
my $custom_charset3_param = "";
my $custom_charset4_param = "";
my $increment_min_param = "";
my $increment_max_param = "";

my $set_options = "";
my $remove_options = "";

foreach my $arg (@ARGV)
{
  if ($switch ne "")
  {
    if ($switch eq "file")
    {
      $output_file = $arg;
    }
    elsif ($switch eq "version")
    {
      $version = $arg;
    }
    elsif ($switch eq "cwd")
    {
      $cwd = $arg;
    }
    elsif ($switch eq "dicts_pos")
    {
      $dicts_pos = $arg;
    }
    elsif ($switch eq "masks_pos")
    {
      $masks_pos = $arg;
    }
    elsif ($switch eq "words_cur")
    {
      $words_cur = $arg;
    }
    elsif ($switch eq "line")
    {
      $cmd_line = $arg;
    }
    elsif ($switch eq "runtime")
    {
      $runtime_param = $arg;
    }
    elsif ($switch eq "session")
    {
      $session_param = $arg;
    }
    elsif ($switch eq "outfile")
    {
      $outfile_param = $arg;
    }
    elsif ($switch eq "outfile-format")
    {
      $outfile_format_param = $arg;
    }
    elsif ($switch eq "status-timer")
    {
      $status_timer_param = $arg;
    }
    elsif ($switch eq "outfile-check-timer")
    {
      $outfile_check_timer_param = $arg;
    }
    elsif ($switch eq "remove-timer")
    {
      $remove_timer_param = $arg;
    }
    elsif ($switch eq "debug-mode")
    {
      $debug_mode_param = $arg;
    }
    elsif ($switch eq "debug-file")
    {
      $debug_file_param = $arg;
    }
    elsif ($switch eq "induction-dir")
    {
      $induction_dir_param = $arg;
    }
    elsif ($switch eq "outfile-check-dir")
    {
      $outfile_check_dir_param = $arg;
    }
    elsif ($switch eq "segment-size")
    {
      $segment_size_param = $arg;
    }
    elsif ($switch eq "gpu-devices")
    {
      $gpu_devices_param = $arg;
    }
    elsif ($switch eq "workload-profile")
    {
      $workload_profile_param = $arg;
    }
    elsif ($switch eq "kernel-accel")
    {
      $gpu_accel_param = $arg;
    }
    elsif ($switch eq "kernel-loops")
    {
      $gpu_loops_param = $arg;
    }
    elsif ($switch eq "gpu-temp-abort")
    {
      $gpu_temp_abort_param = $arg;
    }
    elsif ($switch eq "gpu-temp-retain")
    {
      $gpu_temp_retain_param = $arg;
    }
    elsif ($switch eq "scrypt-tmto")
    {
      $scrypt_tmto_param = $arg;
    }
    elsif ($switch eq "rule-left")
    {
      $rule_left_param = $arg;
    }
    elsif ($switch eq "rule-right")
    {
      $rule_right_param = $arg;
    }
    elsif ($switch eq "rules-file")
    {
      $rules_file_param = $arg;
    }
    elsif ($switch eq "generate-rules")
    {
      $generate_rules_param = $arg;
    }
    elsif ($switch eq "custom-charset1")
    {
      $custom_charset1_param = $arg;
    }
    elsif ($switch eq "custom-charset2")
    {
      $custom_charset2_param = $arg;
    }
    elsif ($switch eq "custom-charset3")
    {
      $custom_charset3_param = $arg;
    }
    elsif ($switch eq "custom-charset4")
    {
      $custom_charset4_param = $arg;
    }
    elsif ($switch eq "increment-min")
    {
      $increment_min_param = $arg;
    }
    elsif ($switch eq "increment-max")
    {
      $increment_max_param = $arg;
    }
    elsif ($switch eq "set")
    {
      $set_options = $arg;
    }
    elsif ($switch eq "rem")
    {
      $remove_options = $arg;
    }

    $switch = "";
  }
  else
  {
    if (($arg eq "-Q") || ($arg eq "--quiet-mode"))
    {
      $quiet_mode = 1;
    }
    elsif (($arg eq "-h") || ($arg eq "--help"))
    {
      usage ($script_name);

      exit (0);
    }
    elsif (($arg eq "-f") || ($arg eq "--file"))
    {
      $switch = "file";
    }
    elsif (($arg eq "-V") || ($arg eq "--version"))
    {
      $switch = "version";
    }
    elsif (($arg eq "-C") || ($arg eq "--cwd"))
    {
      $switch = "cwd";
    }
    elsif (($arg eq "-D") || ($arg eq "--dictpos"))
    {
      $switch = "dicts_pos";
    }
    elsif (($arg eq "-M") || ($arg eq "--maskpos"))
    {
      $switch = "masks_pos";
    }
    elsif (($arg eq "-P") || ($arg eq "--pw_cur"))
    {
      $switch = "words_cur";
    }
    elsif (($arg eq "-L") || ($arg eq "--line"))
    {
      $switch = "line";
    }
    elsif (($arg eq "-q") || ($arg eq "--quiet"))
    {
      $quiet = "1";
    }
    elsif (($arg eq "-s") || ($arg eq "--status"))
    {
      $status = "1";
    }
    elsif (($arg eq "-A") || ($arg eq "--status-automat"))
    {
      $status_automat = "1";
    }
    elsif (($arg eq "-H") || ($arg eq "--outfile-autohex-disable"))
    {
      $outfile_autohex_disable = "1";
    }
    elsif (($arg eq "-v") || ($arg eq "--remove"))
    {
      $remove = "1";
    }
    elsif (($arg eq "-p") || ($arg eq "--potfile-disable"))
    {
      $potfile_disable = "1";
    }
    elsif (($arg eq "-G") || ($arg eq "--logfile-disable"))
    {
      $logfile_disable = "1";
    }
    elsif (($arg eq "-T") || ($arg eq "--gpu-temp-disable"))
    {
      $gpu_temp_disable = "1";
    }
    elsif (($arg eq "-i") || ($arg eq "--increment"))
    {
      $increment = "1";
    }
    elsif (($arg eq "-t") || ($arg eq "--runtime"))
    {
      $switch = "runtime";
    }
    elsif (($arg eq "-E") || ($arg eq "--session"))
    {
      $switch = "session";
    }
    elsif (($arg eq "-o") || ($arg eq "--outfile"))
    {
      $switch = "outfile";
    }
    elsif (($arg eq "-F") || ($arg eq "--outfile-format"))
    {
      $switch = "outfile-format";
    }
    elsif (($arg eq "-U") || ($arg eq "--status-timer"))
    {
      $switch = "status-timer";
    }
    elsif (($arg eq "-e") || ($arg eq "--outfile-check-timer"))
    {
      $switch = "outfile-check-timer";
    }
    elsif (($arg eq "-I") || ($arg eq "--remove-timer"))
    {
      $switch = "remove-timer";
    }
    elsif (($arg eq "-b") || ($arg eq "--debug-mode"))
    {
      $switch = "debug-mode";
    }
    elsif (($arg eq "-B") || ($arg eq "--debug-file"))
    {
      $switch = "debug-file";
    }
    elsif (($arg eq "-N") || ($arg eq "--induction-dir"))
    {
      $switch = "induction-dir";
    }
    elsif (($arg eq "-K") || ($arg eq "--outfile-check-dir"))
    {
      $switch = "outfile-check-dir";
    }
    elsif (($arg eq "-c") || ($arg eq "--segment-size"))
    {
      $switch = "segment-size";
    }
    elsif (($arg eq "-d") || ($arg eq "--gpu-devices"))
    {
      $switch = "gpu-devices";
    }
    elsif (($arg eq "-w") || ($arg eq "--workload-profile"))
    {
      $switch = "workload-profile";
    }
    elsif (($arg eq "-O") || ($arg eq "--optimized-kernel-enable"))
    {
      $optimized_kernel = "1";
    }
    elsif (($arg eq "-n") || ($arg eq "--kernel-accel"))
    {
      $switch = "kernel-accel";
    }
    elsif (($arg eq "-u") || ($arg eq "--kernel-loops"))
    {
      $switch = "kernel-loops";
    }
    elsif (($arg eq "-R") || ($arg eq "--force"))
    {
      $gpu_force = "1";
    }
    elsif (($arg eq "-a") || ($arg eq "--gpu-temp-abort"))
    {
      $switch = "gpu-temp-abort";
    }
    elsif (($arg eq "-m") || ($arg eq "--gpu-temp-retain"))
    {
      $switch = "gpu-temp-retain";
    }
    elsif (($arg eq "-y") || ($arg eq "--scrypt-tmto"))
    {
      $switch = "scrypt-tmto";
    }
    elsif (($arg eq "-j") || ($arg eq "--rule-left"))
    {
      $switch = "rule-left";
    }
    elsif (($arg eq "-k") || ($arg eq "--rule-right"))
    {
      $switch = "rule-right";
    }
    elsif (($arg eq "-r") || ($arg eq "--rules-file"))
    {
      $switch = "rules-file";
    }
    elsif (($arg eq "-g") || ($arg eq "--generate-rules"))
    {
      $switch = "generate-rules";
    }
    elsif (($arg eq "-1") || ($arg eq "--custom-charset1"))
    {
      $switch = "custom-charset1";
    }
    elsif (($arg eq "-2") || ($arg eq "--custom-charset2"))
    {
      $switch = "custom-charset2";
    }
    elsif (($arg eq "-3") || ($arg eq "--custom-charset3"))
    {
      $switch = "custom-charset3";
    }
    elsif (($arg eq "-4") || ($arg eq "--custom-charset4"))
    {
      $switch = "custom-charset4";
    }
    elsif (($arg eq "-x") || ($arg eq "--increment-min"))
    {
      $switch = "increment-min";
    }
    elsif (($arg eq "-Y") || ($arg eq "--increment-max"))
    {
      $switch = "increment-max";
    }
    elsif (($arg eq "-S") || ($arg eq "--set"))
    {
      $switch = "set";
    }
    elsif (($arg eq "-R") || ($arg eq "--rem"))
    {
      $switch = "rem";
    }
    else
    {
      if ($input_file ne "")
      {
        print "ERROR: there is a problem with your command line arguments, please check the usage:\n\n";

        usage ($script_name);

        exit (0);
      }

      $input_file = $arg;
    }
  }
}

# set output_file

if ($output_file eq "")
{
  # default output file

  if ($input_file =~ m/\.restore$/)
  {
    $output_file = $input_file;
    $output_file =~ s/\.restore/_mod.restore/;
  }
  else
  {
    $output_file = $input_file . "_mod.restore";
  }
}


if ($input_file eq $output_file)
{
  print "ERROR: input .restore file and the modified .restore file can't be the same\n";

  exit (1);
}

# check if there are any changes that need to be made to the .restore file

my $restore_file_modified = 0;

if (($version ne "") || ($cwd ne "") || ($dicts_pos ne "") || ($masks_pos ne "") || ($words_cur ne "") || ($cmd_line ne "") || ($quiet ne "") || ($status ne "") || ($status_automat ne "") || ($outfile_autohex_disable ne "") || ($remove ne "") || ($potfile_disable ne "") || ($logfile_disable ne "") || ($gpu_temp_disable ne "") || ($increment ne "") || ($optimized_kernel ne "") || ($runtime_param ne "") || ($session_param ne "") || ($outfile_param ne "") || ($outfile_format_param ne "") || ($status_timer_param ne "") || ($outfile_check_timer_param ne "") || ($remove_timer_param ne "") || ($debug_mode_param ne "") || ($debug_file_param ne "") || ($induction_dir_param ne "") || ($outfile_check_dir_param ne "") || ($segment_size_param ne "") || ($gpu_devices_param ne "") || ($workload_profile_param ne "") || ($gpu_accel_param ne "") || ($gpu_loops_param ne "") || ($gpu_force ne "") || ($gpu_temp_abort_param ne "") || ($gpu_temp_retain_param ne "") || ($scrypt_tmto_param ne "") || ($rule_left_param ne "") || ($rule_right_param ne "") || ($rules_file_param ne "") || ($generate_rules_param ne "") || ($custom_charset1_param ne "") || ($custom_charset2_param ne "") || ($custom_charset3_param ne "") || ($custom_charset4_param ne "") || ($increment_min_param ne "") || ($increment_max_param ne "") || ($set_options ne "") || ($remove_options ne ""))
{
  $restore_file_modified = 1;
}

# print input file

my %file_info = analyze_file ($input_file, $quiet_mode);

if (($quiet_mode == 1) && ($restore_file_modified == 0))
{
  print "\nERROR: you either need to set some modified options for the .restore file or not use --quiet-mode\n";

  exit (1);
}

# set new options (if there are any)

if ($restore_file_modified == 1)
{
  # modify %file_info

  if ($cwd ne "")
  {
    $file_info{'cwd'} = $cwd;
  }

  if ($version ne "")
  {
    $version =~ s/[^0-9]//g;
    $file_info{'version'} = $version;
  }

  if ($dicts_pos ne "")
  {
    if ($dicts_pos !~ m/^[0-9]+$/)
    {
      print "\nERROR: the value specified for the dictionary position must be numeric\n";

      exit (1);
    }

    $file_info{'dicts_pos'} = $dicts_pos;
  }

  if ($masks_pos ne "")
  {
    if ($masks_pos !~ m/^[0-9]+$/)
    {
      print "\nERROR: the value specified for the mask position must be numeric\n";

      exit (1);
    }

    $file_info{'masks_pos'} = $masks_pos;
  }

  if ($words_cur ne "")
  {
    if ($words_cur !~ m/^[0-9]+$/)
    {
      print "\nERROR: the value specified for the current password value must be numeric\n";

      exit (1);
    }

    $file_info{'words_cur'} = $words_cur;
  }

  if (($cmd_line ne "") && (($set_options ne "") && ($remove_options ne "")))
  {
    print "\nERROR: arguments are not compatible, e.g. can't mix --line VALUE with --set VALUE\n";

    exit (1);
  }

  if ($cmd_line ne "")
  {
    $file_info{'argv'} = split_cmd_line ($cmd_line);
    $file_info{'argc'} = ($file_info{'argv'} =~ tr/\n//);
  }
  else
  {
    # some switches

    if ($quiet eq "1")
    {
      add_cmd_line_switch (\%file_info, "--quiet");
    }

    if ($status eq "1")
    {
      add_cmd_line_switch (\%file_info, "--status");
    }

    if ($status_automat eq "1")
    {
      if (! is_already_in_cmd_line ($file_info{'argv'}, "--status"))
      {
        print "\nERROR: the command line switch --status must be set if you want to set --status-automat\n";

        exit (1);
      }

      add_cmd_line_switch (\%file_info, "--status-automat");
    }

    if ($outfile_autohex_disable eq "1")
    {
      add_cmd_line_switch (\%file_info, "--outfile-autohex-disable");
    }

    if ($remove eq "1")
    {
      add_cmd_line_switch (\%file_info, "--remove");
    }

    if ($potfile_disable eq "1")
    {
      add_cmd_line_switch (\%file_info, "--potfile-disable");
    }

    if ($logfile_disable eq "1")
    {
      add_cmd_line_switch (\%file_info, "--logfile-disable");
    }

    if ($gpu_temp_disable eq "1")
    {
      add_cmd_line_switch (\%file_info, "--gpu-temp-disable");
    }

    if ($increment eq "1")
    {
      print "\nWARNING: adding --increment to the command line may or may not work in specific cases\n";

      add_cmd_line_switch (\%file_info, "--increment");
    }

    if ($optimized_kernel eq "1")
    {
      add_cmd_line_switch (\%file_info, "--optimized-kernel-enable");
    }

    # parameters

    if ($runtime_param ne "")
    {
      if ($runtime_param !~ m/^[0-9]+$/)
      {
        print "\nERROR: the --runtime value must be numeric\n";

        exit (1);
      }

      my @options = ("--runtime", "-r");

      add_cmd_line_param (\%file_info, \@options, $runtime_param);
    }

    if ($session_param ne "")
    {
      my @options = ("--session");

      add_cmd_line_param (\%file_info, \@options, $session_param);
    }

    if ($outfile_param ne "")
    {
      my @options = ("--outfile", "-o");

      add_cmd_line_param (\%file_info, \@options, $outfile_param);
    }

    if ($outfile_format_param ne "")
    {
      if ($runtime_param !~ m/^[0-9]+$/)
      {
        print "\nERROR: unsupported value for --outfile-format specified\n";

        exit (1);
      }

      if (($outfile_format_param < 1) || ($outfile_format_param > 15))
      {
        print "\nERROR: the --outfile-format specified is not supported by hashcat\n";

        exit (1);
      }
      my @options = ("--outfile-format");

      add_cmd_line_param (\%file_info, \@options, $outfile_format_param);
    }

    if ($status_timer_param ne "")
    {
      if ($status_timer_param !~ m/^[0-9]+$/)
      {
        print "\nERROR: unsupported value for --status-timer specified, must be numeric\n";

        exit (1);
      }

      if (! is_already_in_cmd_line ($file_info{'argv'}, "--status"))
      {
        print "\nERROR: the command line switch --status must be set if you want to set --status-timer\n";

        exit (1);
      }

      my @options = ("--status-timer");

      add_cmd_line_param (\%file_info, \@options, $status_timer_param);
    }

    if ($outfile_check_timer_param ne "")
    {
      if ($outfile_check_timer_param !~ m/^[0-9]+$/)
      {
        print "\nERROR: unsupported value for --outfile-check-timer specified, must be numeric\n";

        exit (1);
      }

      my @options = ("--outfile-check-timer");

      add_cmd_line_param (\%file_info, \@options, $outfile_check_timer_param);
    }

    if ($remove_timer_param ne "")
    {
      if ($remove_timer_param !~ m/^[0-9]+$/)
      {
        print "\nERROR: unsupported value for --remove-timer specified, must be numeric\n";

        exit (1);
      }

      if (! is_already_in_cmd_line ($file_info{'argv'}, "--remove"))
      {
        print "\nERROR: the command line switch --remove must be set if you want to set --remove-timer\n";

        exit (1);
      }

      my @options = ("--remove-timer");

      add_cmd_line_param (\%file_info, \@options, $remove_timer_param);
    }

    if ($rules_file_param ne "")
    {
      my @options = ("--rules-file", "-r");

      add_cmd_line_param (\%file_info, \@options, $rules_file_param);
    }

    if ($generate_rules_param ne "")
    {
      if ($generate_rules_param !~ m/^[0-9]+$/)
      {
        print "\nERROR: unsupported value for --generate-rules specified, must be numeric\n";

        exit (1);
      }

      my @options = ("--generate-rules", "-g");

      add_cmd_line_param (\%file_info, \@options, $generate_rules_param);
    }

    if ($debug_mode_param ne "")
    {
      if (($debug_mode_param != 1) && ($debug_mode_param != 2) && ($debug_mode_param != 3) && ($debug_mode_param != 4))
      {
        print "\nERROR: unsupported value for --debug-mode specified, must be either 1, 2, 3 or 4\n";

        exit (1);
      }

      if ((! is_already_in_cmd_line ($file_info{'argv'}, "-r")) && (! is_already_in_cmd_line ($file_info{'argv'}, "--rules-file")) &&
          (! is_already_in_cmd_line ($file_info{'argv'}, "-g")) && (! is_already_in_cmd_line ($file_info{'argv'}, "--generate-rules")))
      {
        print "\nERROR: the command line switch --debug-mode requires that hashcat uses some rules\n";

        exit (1);
      }

      my @options = ("--debug-mode");

      add_cmd_line_param (\%file_info, \@options, $debug_mode_param);
    }

    if ($debug_file_param ne "")
    {
      if (! is_already_in_cmd_line ($file_info{'argv'}, "--debug-mode"))
      {
        print "\nERROR: the command line switch --debug-mode must be set if you want to use --debug-file\n";

        exit (1);
      }

      my @options = ("--debug-file");

      add_cmd_line_param (\%file_info, \@options, $debug_file_param);
    }

    if ($induction_dir_param ne "")
    {
      my @options = ("--induction-dir");

      add_cmd_line_param (\%file_info, \@options, $induction_dir_param);
    }

    if ($outfile_check_dir_param ne "")
    {
      my @options = ("--outfile-check-dir");

      add_cmd_line_param (\%file_info, \@options, $outfile_check_dir_param);
    }

    if ($segment_size_param ne "")
    {
      if ($segment_size_param !~ m/^[0-9]+$/)
      {
        print "\nERROR: unsupported value for --segment-size specified, must be numeric\n";

        exit (1);
      }

      my @options = ("--segment-size", "-c");

      add_cmd_line_param (\%file_info, \@options, $segment_size_param);
    }

    if ($gpu_devices_param ne "")
    {
      if ($gpu_devices_param !~ m/^[0-9, ]+$/)
      {
        print "\nERROR: unsupported value for --gpu-devices specified, must be a semi-colon-separated list of numbers\n";

        exit (1);
      }

      my @options = ("--gpu-devices", "-d");

      add_cmd_line_param (\%file_info, \@options, $gpu_devices_param);
    }

    if ($workload_profile_param ne "")
    {
      $workload_profile_param = int ($workload_profile_param);

      if (($workload_profile_param != 1) && ($workload_profile_param != 2) && ($workload_profile_param != 3) && ($workload_profile_param != 4))
      {
        print "\nERROR: the --workload-profile must be either 1, 2, 3, 4\n";

        exit (1);
      }

      my @options = ("--workload-profile", "-w");

      add_cmd_line_param (\%file_info, \@options, $workload_profile_param);
    }

    if ($gpu_accel_param ne "")
    {
      if ($gpu_accel_param !~ m/^[0-9]+$/)
      {
        print "\nERROR: unsupported value for --kernel-accel specified, must be numeric\n";

        exit (1);
      }

      if ((! is_already_in_cmd_line ($file_info{'argv'}, "-w")) && (! is_already_in_cmd_line ($file_info{'argv'}, "--workload-profile")))
      {
        print "\nERROR: setting a value for --kernel-accel is not possible if --workload-profile is set, remove -w if you want to set --kernel-accel\n";

        exit (1);
      }

      my @options = ("-n", "--kernel-accel");

      add_cmd_line_param (\%file_info, \@options, $gpu_accel_param);
    }

    if ($gpu_loops_param ne "")
    {
      if ($gpu_loops_param !~ m/^[0-9]+$/)
      {
        print "\nERROR: unsupported value for --kernel-loops specified, must be numeric\n";

        exit (1);
      }

      if ((! is_already_in_cmd_line ($file_info{'argv'}, "-w")) && (! is_already_in_cmd_line ($file_info{'argv'}, "--workload-profile")))
      {
        print "\nERROR: setting a value for --kernel-loops is not possible if --workload-profile is set, remove -w if you want to set --kernel-loops\n";

        exit (1);
      }

      my @options = ("-u", "--kernel-loops");

      add_cmd_line_param (\%file_info, \@options, $gpu_loops_param);
    }

    if ($gpu_force eq "1")
    {
      print "\nWARNING: adding --force to the command line overrides warnings, do NOT report related errors, Use at your own risk\n";
        
      add_cmd_line_switch (\%file_info, "--force");
    }

    if ($gpu_temp_abort_param ne "")
    {
      if ($gpu_temp_abort_param !~ m/^[0-9]+$/)
      {
        print "\nERROR: unsupported value for --gpu-temp-abort specified, must be numeric\n";

        exit (1);
      }

      if (is_already_in_cmd_line ($file_info{'argv'}, "--gpu-temp-disable"))
      {
        print "\nERROR: the command line switch --gpu-temp-disable can't be set for --gpu-temp-abort\n";

        exit (1);
      }

      my @options = ("--gpu-temp-abort");

      add_cmd_line_param (\%file_info, \@options, $gpu_temp_abort_param);
    }

    if ($gpu_temp_retain_param ne "")
    {
      if ($gpu_temp_retain_param !~ m/^[0-9]+$/)
      {
        print "\nERROR: unsupported value for --gpu-temp-retain specified, must be numeric\n";

        exit (1);
      }

      if (is_already_in_cmd_line ($file_info{'argv'}, "--gpu-temp-retain"))
      {
        print "\nERROR: the command line switch --gpu-temp-disable can't be set for --gpu-temp-retain\n";

        exit (1);
      }

      my @options = ("--gpu-temp-retain");

      add_cmd_line_param (\%file_info, \@options, $gpu_temp_retain_param);
    }

    if ($scrypt_tmto_param ne "")
    {
      if ($scrypt_tmto_param !~ m/^[0-9]+$/)
      {
        print "\nERROR: unsupported value for --scrypt-tmto specified, must be numeric\n";

        exit (1);
      }

      my @options = ("--scrypt-tmto");

      add_cmd_line_param (\%file_info, \@options, $scrypt_tmto_param);
    }

    if ($rule_left_param ne "")
    {
      my @options = ("--rule-left", "-j");

      add_cmd_line_param (\%file_info, \@options, $rule_left_param);
    }

    if ($rule_right_param ne "")
    {
      my @options = ("--rule-right", "-k");

      add_cmd_line_param (\%file_info, \@options, $rule_right_param);
    }

    if ($custom_charset1_param ne "")
    {
      my @options = ("--custom-charset1", "-1");

      add_cmd_line_param (\%file_info, \@options, $custom_charset1_param);
    }

    if ($custom_charset2_param ne "")
    {
      my @options = ("--custom-charset2", "-2");

      add_cmd_line_param (\%file_info, \@options, $custom_charset2_param);
    }

    if ($custom_charset3_param ne "")
    {
      my @options = ("--custom-charset3", "-3");

      add_cmd_line_param (\%file_info, \@options, $custom_charset3_param);
    }

    if ($custom_charset4_param ne "")
    {
      my @options = ("--custom-charset4", "-4");

      add_cmd_line_param (\%file_info, \@options, $custom_charset4_param);
    }

    if ($increment_min_param ne "")
    {
      if (is_already_in_cmd_line ($file_info{'argv'}, "--increment"))
      {
        print "\nERROR: the command line switch --increment is needed for --increment-min\n";

        exit (1);
      }

      my @options = ("--increment-min");

      add_cmd_line_param (\%file_info, \@options, $increment_min_param);
    }

    if ($increment_max_param ne "")
    {
      if (is_already_in_cmd_line ($file_info{'argv'}, "--increment"))
      {
        print "\nERROR: the command line switch --increment is needed for --increment-max\n";

        exit (1);
      }

      my @options = ("--increment-max");

      add_cmd_line_param (\%file_info, \@options, $increment_max_param);
    }

    # REMOVE list of options

    if ($remove_options ne "")
    {
      my @splitted_list = split_on_commas ($remove_options);

      foreach my $option (@splitted_list)
      {
        my @splitted_option = split_on_first_equal_sign ($option);

        if ($splitted_option[0] !~ /^-/)
        {
          print "ERROR: command line switch/parameter must start with a hypen\n";

          exit (1);
        }

        if (scalar (@splitted_option) == 2)
        {
          rem_cmd_line_param (\%file_info, $splitted_option[0], $splitted_option[1]);
        }
        else
        {
          rem_cmd_line_switch (\%file_info, $splitted_option[0]);
        }
      }
    }

    # SET list of options

    if ($set_options ne "")
    {
      my @splitted_list = split_on_commas ($set_options);

      foreach my $option (@splitted_list)
      {
        my @splitted_option = split_on_first_equal_sign ($option);

        if ($splitted_option[0] !~ /^-/)
        {
          print "ERROR: command line switch/parameter must start with a hypen\n";

          exit (1);
        }

        if (is_already_in_cmd_line ($file_info{'argv'}, $splitted_option[0]))
        {
          print "\nERROR: the command line switch '$splitted_option[0]' is already present in your command line\n";

          exit (1);
        }

        if (scalar (@splitted_option) == 2)
        {
          my @options = ($splitted_option[0]);

          add_cmd_line_param (\%file_info, \@options, $splitted_option[1]);
        }
        else
        {
          add_cmd_line_switch (\%file_info, $splitted_option[0]);
        }
      }
    }
  }

  # write new file

  write_modified_file ($output_file, \%file_info);

  # print newly created file

  if ($quiet_mode == 0)
  {
    print "\n'$output_file' was successfully written.\n";
    print "\nModified .restore file:\n\n";
  }

  analyze_file ($output_file, $quiet_mode);
}

exit (0);
