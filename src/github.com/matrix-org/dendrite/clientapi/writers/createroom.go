package writers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/matrix-org/dendrite/clientapi/auth"
	"github.com/matrix-org/dendrite/clientapi/config"
	"github.com/matrix-org/dendrite/clientapi/events"
	"github.com/matrix-org/dendrite/clientapi/httputil"
	"github.com/matrix-org/dendrite/clientapi/jsonerror"
	"github.com/matrix-org/dendrite/common"
	"github.com/matrix-org/dendrite/roomserver/api"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/util"
	sarama "gopkg.in/Shopify/sarama.v1"
)

// https://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-createroom
type createRoomRequest struct {
	Invite          []string               `json:"invite"`
	Name            string                 `json:"name"`
	Visibility      string                 `json:"visibility"`
	Topic           string                 `json:"topic"`
	Preset          string                 `json:"preset"`
	CreationContent map[string]interface{} `json:"creation_content"`
	InitialState    json.RawMessage        `json:"initial_state"` // TODO
	RoomAliasName   string                 `json:"room_alias_name"`
}

func (r createRoomRequest) Validate() *util.JSONResponse {
	whitespace := "\t\n\x0b\x0c\r " // https://docs.python.org/2/library/string.html#string.whitespace
	// https://github.com/matrix-org/synapse/blob/v0.19.2/synapse/handlers/room.py#L81
	// Synapse doesn't check for ':' but we will else it will break parsers badly which split things into 2 segments.
	if strings.ContainsAny(r.RoomAliasName, whitespace+":") {
		return &util.JSONResponse{
			Code: 400,
			JSON: jsonerror.BadJSON("room_alias_name cannot contain whitespace"),
		}
	}
	for _, userID := range r.Invite {
		// TODO: We should put user ID parsing code into gomatrixserverlib and use that instead
		//       (see https://github.com/matrix-org/gomatrixserverlib/blob/3394e7c7003312043208aa73727d2256eea3d1f6/eventcontent.go#L347 )
		//       It should be a struct (with pointers into a single string to avoid copying) and
		//       we should update all refs to use UserID types rather than strings.
		// https://github.com/matrix-org/synapse/blob/v0.19.2/synapse/types.py#L92
		if len(userID) == 0 || userID[0] != '@' {
			return &util.JSONResponse{
				Code: 400,
				JSON: jsonerror.BadJSON("user id must start with '@'"),
			}
		}
		parts := strings.SplitN(userID[1:], ":", 2)
		if len(parts) != 2 {
			return &util.JSONResponse{
				Code: 400,
				JSON: jsonerror.BadJSON("user id must be in the form @localpart:domain"),
			}
		}
	}
	return nil
}

// https://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-createroom
type createRoomResponse struct {
	RoomID    string `json:"room_id"`
	RoomAlias string `json:"room_alias,omitempty"` // in synapse not spec
}

// fledglingEvent is a helper representation of an event used when creating many events in succession.
type fledglingEvent struct {
	Type     string
	StateKey string
	Content  interface{}
}

// CreateRoom implements /createRoom
func CreateRoom(req *http.Request, cfg config.ClientAPI, producer sarama.SyncProducer) util.JSONResponse {
	// TODO: Check room ID doesn't clash with an existing one, and we
	//       probably shouldn't be using pseudo-random strings, maybe GUIDs?
	roomID := fmt.Sprintf("!%s:%s", util.RandomString(16), cfg.ServerName)
	return createRoom(req, cfg, roomID, producer)
}

// createRoom implements /createRoom
func createRoom(req *http.Request, cfg config.ClientAPI, roomID string, producer sarama.SyncProducer) util.JSONResponse {
	logger := util.GetLogger(req.Context())
	userID, resErr := auth.VerifyAccessToken(req)
	if resErr != nil {
		return *resErr
	}
	var r createRoomRequest
	resErr = httputil.UnmarshalJSONRequest(req, &r)
	if resErr != nil {
		return *resErr
	}
	// TODO: apply rate-limit

	if resErr = r.Validate(); resErr != nil {
		return *resErr
	}

	// TODO: visibility/presets/raw initial state/creation content

	// TODO: Create room alias association

	logger.WithFields(log.Fields{
		"userID": userID,
		"roomID": roomID,
	}).Info("Creating new room")

	// Remember events we've built and key off the state tuple so we can look them up easily when filling in auth_events
	builtEventMap := make(map[common.StateKeyTuple]*gomatrixserverlib.Event)
	var builtEvents []*gomatrixserverlib.Event

	// send events into the room in order of:
	//  1- m.room.create
	//  2- room creator join member
	//  3- m.room.power_levels
	//  4- m.room.canonical_alias (opt) TODO
	//  5- m.room.join_rules
	//  6- m.room.history_visibility
	//  7- m.room.guest_access (opt) TODO
	//  8- other initial state items TODO
	//  9- m.room.name (opt)
	//  10- m.room.topic (opt)
	//  11- invite events (opt) - with is_direct flag if applicable TODO
	//  12- 3pid invite events (opt) TODO
	//  13- m.room.aliases event for HS (if alias specified) TODO
	// This differs from Synapse slightly. Synapse would vary the ordering of 3-7
	// depending on if those events were in "initial_state" or not. This made it
	// harder to reason about, hence sticking to a strict static ordering.
	// TODO: Synapse has txn/token ID on each event. Do we need to do this here?
	eventsToMake := []fledglingEvent{
		{"m.room.create", "", events.CreateContent{Creator: userID}},
		{"m.room.member", userID, events.MemberContent{Membership: "join"}}, // TODO: Set avatar_url / displayname
		{"m.room.power_levels", "", events.InitialPowerLevelsContent(userID)},
		// TODO: m.room.canonical_alias
		{"m.room.join_rules", "", events.JoinRulesContent{"public"}},                 // FIXME: Allow this to be changed
		{"m.room.history_visibility", "", events.HistoryVisibilityContent{"joined"}}, // FIXME: Allow this to be changed
		// TODO: m.room.guest_access
		// TODO: Other initial state items
		// TODO: m.room.name
		// TODO: m.room.topic
		// TODO: invite events
		// TODO: 3pid invite events
		// TODO m.room.aliases
	}

	authEvents := authEventProvider{builtEventMap}
	for i, e := range eventsToMake {
		depth := i + 1 // depth starts at 1

		builder := gomatrixserverlib.EventBuilder{
			Sender:   userID,
			RoomID:   roomID,
			Type:     e.Type,
			StateKey: &e.StateKey,
			Depth:    int64(depth),
		}
		builder.SetContent(e.Content)
		if i > 0 {
			builder.PrevEvents = []gomatrixserverlib.EventReference{builtEvents[i-1].EventReference()}
		}
		ev, err := buildEvent(&builder, builtEventMap, cfg)
		if err != nil {
			return util.ErrorResponse(err)
		}

		if err := gomatrixserverlib.Allowed(*ev, &authEvents); err != nil {
			return util.ErrorResponse(err)
		}

		// Add the event to the list of auth events
		builtEventMap[common.StateKeyTuple{e.Type, e.StateKey}] = ev
		builtEvents = append(builtEvents, ev)
	}

	// send events to the room server
	msgs, err := eventsToMessages(builtEvents)
	if err != nil {
		return util.ErrorResponse(err)
	}
	if err = producer.SendMessages(msgs); err != nil {
		return util.ErrorResponse(err)
	}

	return util.JSONResponse{
		Code: 200,
		JSON: builtEvents,
	}
}

// buildEvent fills out auth_events for the builder then builds the event
func buildEvent(builder *gomatrixserverlib.EventBuilder,
	events map[common.StateKeyTuple]*gomatrixserverlib.Event,
	cfg config.ClientAPI) (*gomatrixserverlib.Event, error) {

	eventsNeeded, err := gomatrixserverlib.StateNeededForEventBuilder(builder)
	if err != nil {
		return nil, err
	}
	builder.AuthEvents = authEventsFromStateNeeded(eventsNeeded, events)
	eventID := fmt.Sprintf("$%s:%s", util.RandomString(16), cfg.ServerName)
	now := time.Now()
	event, err := builder.Build(eventID, now, cfg.ServerName, cfg.KeyID, cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot build event %s : Builder failed to build. %s", builder.Type, err)
	}
	return &event, nil
}

func authEventsFromStateNeeded(eventsNeeded gomatrixserverlib.StateNeeded,
	events map[common.StateKeyTuple]*gomatrixserverlib.Event) (authEvents []gomatrixserverlib.EventReference) {

	// These events are only "needed" if they exist, so if they don't exist we can safely ignore them.
	if eventsNeeded.Create {
		ev := events[common.StateKeyTuple{"m.room.create", ""}]
		if ev != nil {
			authEvents = append(authEvents, ev.EventReference())
		}
	}
	if eventsNeeded.JoinRules {
		ev := events[common.StateKeyTuple{"m.room.join_rules", ""}]
		if ev != nil {
			authEvents = append(authEvents, ev.EventReference())
		}
	}
	if eventsNeeded.PowerLevels {
		ev := events[common.StateKeyTuple{"m.room.power_levels", ""}]
		if ev != nil {
			authEvents = append(authEvents, ev.EventReference())
		}
	}

	for _, userID := range eventsNeeded.Member {
		ev := events[common.StateKeyTuple{"m.room.member", userID}]
		if ev != nil {
			authEvents = append(authEvents, ev.EventReference())
		}
	}
	for _, token := range eventsNeeded.ThirdPartyInvite {
		ev := events[common.StateKeyTuple{"m.room.member", token}]
		if ev != nil {
			authEvents = append(authEvents, ev.EventReference())
		}
	}
	return
}

func eventsToMessages(events []*gomatrixserverlib.Event) ([]*sarama.ProducerMessage, error) {
	msgs := make([]*sarama.ProducerMessage, len(events))
	for i, e := range events {
		var m sarama.ProducerMessage

		// map auth event references to IDs
		var authEventIDs []string
		for _, ref := range e.AuthEvents() {
			authEventIDs = append(authEventIDs, ref.EventID)
		}

		ire := api.InputRoomEvent{
			Kind:         api.KindNew,
			Event:        e.JSON(),
			AuthEventIDs: authEventIDs,
		}

		value, err := json.Marshal(ire)
		if err != nil {
			return nil, err
		}
		m.Topic = "clientapiOutput" // TODO: Make this customisable like roomserver is?
		m.Key = sarama.StringEncoder(e.EventID())
		m.Value = sarama.ByteEncoder(value)
		msgs[i] = &m
	}
	return msgs, nil
}

type authEventProvider struct {
	events map[common.StateKeyTuple]*gomatrixserverlib.Event
}

func (a *authEventProvider) Create() (ev *gomatrixserverlib.Event, err error) {
	return a.events[common.StateKeyTuple{"m.room.create", ""}], nil
}

func (a *authEventProvider) JoinRules() (ev *gomatrixserverlib.Event, err error) {
	return a.events[common.StateKeyTuple{"m.room.join_rules", ""}], nil
}

func (a *authEventProvider) PowerLevels() (ev *gomatrixserverlib.Event, err error) {
	return a.events[common.StateKeyTuple{"m.room.power_levels", ""}], nil
}

func (a *authEventProvider) Member(stateKey string) (ev *gomatrixserverlib.Event, err error) {
	return a.events[common.StateKeyTuple{"m.room.member", stateKey}], nil
}

func (a *authEventProvider) ThirdPartyInvite(stateKey string) (ev *gomatrixserverlib.Event, err error) {
	return a.events[common.StateKeyTuple{"m.room.third_party_invite", stateKey}], nil
}
