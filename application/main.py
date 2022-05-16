import fnmatch
import glob
import multiprocessing as mp
import os
import re
import subprocess
import exportToDataset
import label_remaining
import processAndDeclareLabels
import sort_remove_dups

def sort_remove_duplicates(in_commentsfile, out_commentsfile):
    infile = in_commentsfile
    outfile = open(out_commentsfile, "w")
    lines_seen = set()  # set() # holds lines already seen

    with open(infile, "r") as f:
        lines = f.readlines()
        for line, r in enumerate(lines):
            try:
                thisLine = lines[line]
                nextLine = lines[line + 1]
                prevLine = lines[line - 1]
            except IndexError:
                pass

            label = thisLine.split(":")[-1]
            framenum = thisLine.split(":")[0]

            if ((framenum not in lines_seen) and not (re.match("T1071.001", label))):
                outfile.write(thisLine)
                lines_seen.add(framenum)

            elif (framenum not in lines_seen and re.match("T1071.001", label)):
                if thisLine == nextLine:
                    pass
                if (re.match(f"^\-[a]\s[{framenum}]*\:[T]([0-9]*\.[0-9]*|[0-9]*)\s$", nextLine)):
                    pass
                else:
                    outfile.write(thisLine)
                    lines_seen.add(framenum)

            elif framenum in lines_seen:
                if (re.match(f"^\-[a]\s[{framenum}]*\:[T]([0-9]*\.[0-9]*|[0-9]*)\s$", prevLine) and re.match("T1071.001", label)):
                    pass
                elif (prevLine == thisLine):
                    pass
                else:
                    outfile.write(thisLine)
                    lines_seen.add(framenum)

        outfile.close()

def prepare_labeling(commentsfile):
    os.system(f'split -l 17000 -d --additional-suffix=.txt {commentsfile} file')
    for file in os.listdir('.'):
        if fnmatch.fnmatch(file, "file*.txt"):  # include dot-files]  # Linux
            print(file)
            with open(file) as f_input:
                data = f_input.read().rstrip('\n')

            with open(file, 'w') as f_output:
                f_output.write(data)
            os.system(f'mv {file} tempFiles/')


def main():
    network_logfile = "data/merged_eth0-eth1-original-copy.pcapng" # merged pcap for experiment: eth1 = caldera, c2, background, eth0 = ghosts, benign
    caldera_reportfile = "data/mandag-siste_full-report.json"
    comments_file = "tempFiles/comments.txt"
    comments_sorted = "tempFiles/comments_sorted.txt"
    comments_sorted_removedDups = "tempFiles/comments_removed_dups.txt"

    ip_vicitm = '192.168.56.104'
    ip_attacker = '192.168.56.106'
    background_ips = ['192.168.56.101', '192.168.56.102', '192.168.56.103', '192.168.56.104', '192.168.56.105']

	# Call functions to start the labelling process:
    pool = mp.Pool(mp.cpu_count())
    pool.apply_async(processAndDeclareLabels.label_background_benign(network_logfile, ip_vicitm, ip_attacker, comments_file, caldera_reportfile, background_ips))
    pool.close()

    # Sort and remove duplicate entries in commentsfile:
    print("Sorting the commentsfile and removing duplicate lines so nothing is labelled twice!")
    os.system(f'sort -k 2n {comments_file} > {comments_sorted}')
    pool = mp.Pool(mp.cpu_count())
    pool.apply_async(sort_remove_dups.sort_remove_duplicates(comments_sorted, comments_sorted_removedDups))
    pool.close()


    # Split the commentsfile, use these files to label packets, export to smaller pcap files.
    prepare_labeling(comments_sorted_removedDups)
    subprocess.run(f"./labelBackground.sh {network_logfile}", shell=True)
    print("Done preparing labels and separating into smaller pcap-files.")

    labeled_file = network_logfile.split("/")[-1].split(".pcapng")[0] + "-labeled.pcapng"
    print("Name of labeled file: ", labeled_file)

    os.chdir("./tempFiles")
    segmented_pcaps = glob.glob("[0-9]*.pcapng")
    seg_as_string = ' '.join(segmented_pcaps)
    print(seg_as_string)

    print("Merging all the smaller pcap files into one large PCAP!")
    print(os.system(f'mergecap -w ../{labeled_file} {seg_as_string}'))

    #Search to see if the file exists/was created:
    os.chdir("..")
    os.chdir(".")
    if glob.glob("*-labeled.pcapng"):
        print(f"Found the file {labeled_file}. \n")
    else:
        print(f'Could not find the file {labeled_file}. \n')
        exit(0)


    print("***************")
    print("Starting to export the file to JSON-format.")
    exportToDataset.export_to_json(labeled_file)
    exportToDataset.export_to_csv(labeled_file)
    print("Files successfully created! Now performing some final editing...")
    basename = labeled_file.split(".pcapng")[0]
    json_labeled_file =  basename + ".json"
    csv_labeled_file =  basename + ".csv"
    subprocess.run(f"./replace.sh {csv_labeled_file} 0 {json_labeled_file}", shell=True)

    print("\nDone with all file processing!")
    print("Script is finished.")

	
if __name__ == "__main__":
    main()
