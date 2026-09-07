package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"fencer/cli/internal/operations"
)

var (
	detectionAssignEmail string
	detectionAssignMe    bool

	detectionResolveAs string
)

var detectionAssignCmd = &cobra.Command{
	Use:         "assign <slug>",
	Short:       "Assign a detection to a user",
	Args:        cobra.ExactArgs(1),
	Annotations: map[string]string{operationAnnotation: operations.DetectionsAssign.Name},
	RunE:        runDetectionAssign,
}

var detectionUnassignCmd = &cobra.Command{
	Use:         "unassign <slug>",
	Short:       "Clear a detection's assignee",
	Args:        cobra.ExactArgs(1),
	Annotations: map[string]string{operationAnnotation: operations.DetectionsUnassign.Name},
	RunE:        runDetectionUnassign,
}

var detectionInvestigateCmd = &cobra.Command{
	Use:         "investigate <slug>",
	Short:       "Mark a detection as under investigation",
	Args:        cobra.ExactArgs(1),
	Annotations: map[string]string{operationAnnotation: operations.DetectionsInvestigate.Name},
	RunE:        runDetectionInvestigate,
}

var detectionResolveCmd = &cobra.Command{
	Use:         "resolve <slug>",
	Short:       "Resolve a detection (requires --as false-positive or --as true-positive)",
	Args:        cobra.ExactArgs(1),
	Annotations: map[string]string{operationAnnotation: operations.DetectionsResolve.Name},
	RunE:        runDetectionResolve,
}

var detectionReopenCmd = &cobra.Command{
	Use:         "reopen <slug>",
	Short:       "Re-open a detection (transition back to new)",
	Args:        cobra.ExactArgs(1),
	Annotations: map[string]string{operationAnnotation: operations.DetectionsReopen.Name},
	RunE:        runDetectionReopen,
}

func init() {
	detectionCmd.AddCommand(
		detectionAssignCmd,
		detectionUnassignCmd,
		detectionInvestigateCmd,
		detectionResolveCmd,
		detectionReopenCmd,
	)

	af := detectionAssignCmd.Flags()
	af.StringVar(&detectionAssignEmail, "email", "", "Assign to the user with this email")
	af.BoolVar(&detectionAssignMe, "me", false, "Assign to the current user")

	rf := detectionResolveCmd.Flags()
	rf.StringVar(&detectionResolveAs, "as", "", "Resolution kind: false-positive|true-positive")
	if err := detectionResolveCmd.MarkFlagRequired("as"); err != nil {
		panic(err)
	}
}

func runDetectionAssign(cmd *cobra.Command, args []string) error {
	org, err := resolveOrgSlug()
	if err != nil {
		return err
	}
	slug := args[0]

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	_, email, err := resolveUserID(client, org, detectionAssignEmail, detectionAssignMe)
	if err != nil {
		return err
	}

	if err := promptConfirm(fmt.Sprintf("Assign detection %s to %s?", slug, email)); err != nil {
		return err
	}

	d, err := operations.DetectionsAssign.Execute(cmd.Context(), client, operations.DetectionsAssignInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: org},
		Slug:              slug,
		Email:             detectionAssignEmail,
		Me:                detectionAssignMe,
	})
	if err != nil {
		return err
	}
	return detectionActionOutput(d, fmt.Sprintf("Assigned detection %s to %s", slug, email))
}

func runDetectionUnassign(cmd *cobra.Command, args []string) error {
	org, err := resolveOrgSlug()
	if err != nil {
		return err
	}
	slug := args[0]

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	current, err := operations.DetectionsGet.Execute(cmd.Context(), client, operations.DetectionsGetInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: org},
		Slug:              slug,
	})
	if err != nil {
		return err
	}
	if current.AssigneeEmail == "" {
		return writeJSONOrText(operations.DetectionsUnassignOutput{
			Detection:         current,
			AlreadyUnassigned: true,
		}, fmt.Sprintf("Detection %s is already unassigned", slug))
	}

	if err := promptConfirm(fmt.Sprintf("Unassign detection %s from %s?", slug, current.AssigneeEmail)); err != nil {
		return err
	}

	out, err := operations.DetectionsUnassign.Execute(cmd.Context(), client, operations.DetectionsUnassignInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: org},
		Slug:              slug,
	})
	if err != nil {
		return err
	}
	if out.AlreadyUnassigned {
		return writeJSONOrText(out, fmt.Sprintf("Detection %s is already unassigned", slug))
	}
	return detectionActionOutput(out.Detection, fmt.Sprintf("Unassigned detection %s from %s", slug, out.PreviousAssignee))
}

func runDetectionInvestigate(cmd *cobra.Command, args []string) error {
	org, err := resolveOrgSlug()
	if err != nil {
		return err
	}
	slug := args[0]

	if err := promptConfirm(fmt.Sprintf("Transition detection %s to under_investigation?", slug)); err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	d, err := operations.DetectionsInvestigate.Execute(cmd.Context(), client, operations.DetectionsInvestigateInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: org},
		Slug:              slug,
	})
	if err != nil {
		return err
	}
	return detectionActionOutput(d, fmt.Sprintf("Detection %s under investigation", slug))
}

func runDetectionResolve(cmd *cobra.Command, args []string) error {
	status, err := operations.DetectionResolveStatus(detectionResolveAs)
	if err != nil {
		return fmt.Errorf("--as must be one of false-positive, true-positive")
	}
	label := "resolved as false positive"
	if detectionResolveAs == "true-positive" {
		label = "resolved as true positive"
	}

	org, err := resolveOrgSlug()
	if err != nil {
		return err
	}
	slug := args[0]

	if err := promptConfirm(fmt.Sprintf("Transition detection %s to %s?", slug, status)); err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	d, err := operations.DetectionsResolve.Execute(cmd.Context(), client, operations.DetectionsResolveInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: org},
		Slug:              slug,
		As:                detectionResolveAs,
	})
	if err != nil {
		return err
	}
	return detectionActionOutput(d, fmt.Sprintf("Detection %s %s", slug, label))
}

func runDetectionReopen(cmd *cobra.Command, args []string) error {
	org, err := resolveOrgSlug()
	if err != nil {
		return err
	}
	slug := args[0]

	if err := promptConfirm(fmt.Sprintf("Transition detection %s to new?", slug)); err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	d, err := operations.DetectionsReopen.Execute(cmd.Context(), client, operations.DetectionsReopenInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: org},
		Slug:              slug,
	})
	if err != nil {
		return err
	}
	return detectionActionOutput(d, fmt.Sprintf("Detection %s re-opened", slug))
}

func detectionActionOutput(d any, tableMsg string) error {
	if outputFormat == "json" {
		return outputJSON(d)
	}
	fmt.Println(tableMsg)
	return nil
}
